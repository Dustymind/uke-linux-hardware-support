// SPDX-License-Identifier: MIT
#include "layout.hpp"
#include "cli.hpp"
#include <algorithm>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
namespace uke::layout {
namespace fs=std::filesystem;
namespace {
struct Cancel {};
std::string dialog(const std::vector<std::string>& options) {
    char temporary[]="/run/uke-layout-ui-XXXXXX";ure::Fd fd(mkstemp(temporary));need(fd.get()>=0,"Cannot allocate private terminal UI output");unlink(temporary);
    std::vector<std::string> args{native_tool("dialog"),"--mouse","--backtitle","Uke storage manager","--no-collapse","--output-fd",std::to_string(fd.get())};args.insert(args.end(),options.begin(),options.end());
    const auto result=run(args,{},fd.get(),true);if(result.status==1||result.status==255)throw Cancel{};need(result.status==0,"Terminal dialog failed");
    need(lseek(fd.get(),0,SEEK_SET)==0,"Cannot read terminal selection");std::string out;char buffer[1024];ssize_t n;while((n=::read(fd.get(),buffer,sizeof(buffer)))>0){need(out.size()+size_t(n)<=16384,"Oversized terminal selection");out.append(buffer,size_t(n));}need(n==0,"Cannot read terminal selection");return out;
}
std::string input(const std::string& prompt,const std::string& initial={}){return dialog({"--inputbox",prompt,"12","78",initial});}
std::string menu(const std::string& prompt,const std::vector<std::string>& pairs) {
    std::vector<std::string> args{"--menu",prompt,"22","90","13"};args.insert(args.end(),pairs.begin(),pairs.end());return dialog(args);
}
std::string menu(const std::string& prompt,std::initializer_list<const char*> pairs) {
    std::vector<std::string> options;for(const auto* pair:pairs)options.emplace_back(pair);return menu(prompt,options);
}
void notice(const std::string& message){dialog({"--msgbox",message,"24","95"});}
bool yes(const std::string& message){try{dialog({"--defaultno","--yesno",message,"20","90"});return true;}catch(const Cancel&){return false;}}
void trusted(const fs::path& directory) {
    need(directory.is_absolute()&&directory==directory.lexically_normal(),"Use an absolute normalized journal path");fs::path current="/";
    for(const auto& part:directory.relative_path()){current/=part;struct stat st{};need(!lstat(current.c_str(),&st)&&S_ISDIR(st.st_mode)&&st.st_uid==0&&!(st.st_mode&0022),"Journal ancestors must be real root-owned directories without group/other write permission");}
}
void copy_original(const fs::path& source,const fs::path& destination) {
    ure::gpt_backup_verify(source);auto out=ure::private_directory(destination,true);auto in=ure::private_directory(source,false);
    for(const auto* name:{"manifest.json","partition-table.json","SHA256SUMS","protective_mbr.bin","primary_header.bin","primary_table.bin","backup_header.bin","backup_table.bin"}) {
        const auto data=in.read(name,4*1024*1024);auto file=out.open(name,O_WRONLY|O_CREAT|O_EXCL,0600);size_t done=0;
        while(done<data.size()){const auto n=write(file.get(),data.data()+done,data.size()-done);if(n<0&&errno==EINTR)continue;need(n>0,"Cannot copy original GPT proof");done+=size_t(n);}need(!fsync(file.get()),"Cannot synchronize original GPT proof");
    }need(!fsync(out.fd()),"Cannot synchronize original GPT directory");ure::gpt_backup_verify(destination);
}
std::string filesystem(bool userdata,const std::string& selected="ext4") {
    std::vector<std::string> choices;
    for(const auto& cap:native_capabilities()) {
        const auto type=cap["filesystem"].asString();if(cap["available"]!=true)continue;
        if(userdata&&type!="ext4"&&type!="f2fs"&&type!="btrfs"&&type!="xfs")continue;
        choices.push_back(type);choices.push_back(type==selected?"Current filesystem":cap.get("limitation","Native formatter and checker").asString());
    }need(!choices.empty(),"No reviewed native filesystem tools are installed");return menu("Filesystem for this volume",choices);
}
constexpr std::uint64_t gib=1073741824ULL;
std::string gib_text(std::uint64_t bytes) {
    if(bytes<gib)return std::to_string(bytes/1048576)+" MiB";
    const auto tenths=bytes/(gib/10);return std::to_string(tenths/10)+"."+std::to_string(tenths%10)+" GiB";
}
// Mirrors ure::minimum() in shared/recovery/multiboot.cpp. That function is not
// exported from the imported component, so these values only shape prompts; the
// planner remains the authority and still refuses anything below its own floor.
std::map<std::string,std::uint64_t> role_minimums() {
    return {{"esp",512000000},{"linux_boot",512000000},{"linux",40*gib},{"linux2",40*gib},
            {"linux_swap",gib},{"windows",50*gib},{"shared",32*1048576},{"userdata",64*gib}};
}
std::optional<std::uint64_t> requested_bytes(const std::string& size,const std::string& unit,std::uint64_t pool) {
    if(size.empty()||size.size()>24||size.front()=='.'||size.front()==',')return std::nullopt;
    std::uint64_t whole=0,fraction=0,scale=1000000;bool dot=false;unsigned places=0;
    for(char c:size) {
        if(c=='.'||c==','){if(dot)return std::nullopt;dot=true;continue;}
        if(c<'0'||c>'9')return std::nullopt;
        const auto digit=static_cast<unsigned>(c-'0');
        if(dot){if(++places>6)return std::nullopt;scale/=10;fraction+=digit*scale;}
        else{if(whole>(UINT64_MAX/1000000-digit)/10)return std::nullopt;whole=whole*10+digit;}
    }
    if(dot&&places==0)return std::nullopt;
    const auto scaled=static_cast<__int128>(whole)*1000000+fraction;
    __int128 bytes=0;
    if(unit=="%")bytes=scaled*pool/(100*1000000);
    else {
        const std::uint64_t factor=unit=="GiB"?gib:unit=="GB"?1000000000ULL:unit=="MiB"?1048576ULL:unit=="MB"?1000000ULL:0;
        if(!factor)return std::nullopt;
        bytes=scaled*factor/1000000;
    }
    if(bytes<0||bytes>INT64_MAX)return std::nullopt;
    return static_cast<std::uint64_t>(bytes);
}
std::uint64_t initial_bytes(const std::string& role,std::uint64_t floor,std::uint64_t maximum) {
    const auto preferred=role=="esp"||role=="linux_boot"?gib:role=="linux_swap"?8*gib:role=="windows"?50*gib:std::max(floor,maximum/2);
    return std::min(preferred,maximum);
}
std::string size_text(std::uint64_t bytes,const std::string& unit,std::uint64_t pool,bool up,unsigned places) {
    std::uint64_t scale=1;for(unsigned i=0;i<places;++i)scale*=10;
    const std::uint64_t factor=unit=="GiB"?gib:unit=="GB"?1000000000ULL:unit=="MiB"?1048576ULL:1000000ULL;
    const auto numerator=unit=="%"?static_cast<__int128>(bytes)*100*scale:static_cast<__int128>(bytes)*scale;
    const auto denominator=unit=="%"?static_cast<__int128>(pool):static_cast<__int128>(factor);
    auto scaled=numerator/denominator;if(up && numerator%denominator)++scaled;
    const auto fraction=static_cast<std::uint64_t>(scaled%scale);const auto digits=std::to_string(fraction);
    return std::to_string(static_cast<std::uint64_t>(scaled/scale))+"."+std::string(places>digits.size()?places-digits.size():0,'0')+digits;
}
Value layout_request(bool single,const std::string& fs,std::uint64_t pool) {
    Value request;request["schema"]=1;request["format"]="uke-multiboot-request";request["action"]=single?"restore-default":"setup";request["keep_userdata"]=true;request["advanced"]=false;request["userdata_filesystem"]=fs;request["partitions"]=Value(Json::arrayValue);
    if(single)return request;
    const auto floors=role_minimums();const auto reserve=floors.at("userdata");
    need(pool>reserve,"Original userdata is too small to keep Android and add Linux");
    const auto budget=pool-reserve;
    std::vector<std::string> chosen;
    for(;;) {
        const auto roles=dialog({"--separate-output","--checklist","Original userdata is "+gib_text(pool)+"; at least "+gib_text(reserve)+" stays for Android, leaving "+gib_text(budget)+" for every Linux volume together.","23","92","10","esp","EFI system partition (512 MiB - 4 GiB)","on","linux_boot","Separate Linux boot (at least 512 MiB)","on","linux","Linux root (at least 40 GiB)","on","linux_swap","Linux swap (at least 1 GiB)","off","windows","Windows root / NTFS (at least 50 GiB)","off","shared","Shared data","off","linux2","Second Linux root (at least 40 GiB)","off"});
        std::istringstream selected(roles);chosen.clear();std::string role;
        while(std::getline(selected,role)){if(role.empty())continue;need(ure::identifier(role),"Invalid role selection");need(floors.contains(role),"Unknown multiboot role");chosen.push_back(role);}
        if(chosen.empty()){notice("Select at least one volume to place beside Android.");continue;}
        std::uint64_t needed=0;for(const auto& name:chosen)needed+=floors.at(name);
        if(needed<=budget)break;
        notice("The selected volumes need "+gib_text(needed)+" before any data, but only "+gib_text(budget)+" is available once Android keeps its "+gib_text(reserve)+".\n\nDeselect a volume and select again.");
    }
    std::uint64_t minima=0;for(const auto& name:chosen)minima+=floors.at(name);
    request["advanced"]=menu("Layout options",{"standard","Standard labels and order","advanced","Custom labels and order; userdata always first"})=="advanced";
    Value partitions(Json::arrayValue);
    for(;;) {
        partitions=Value(Json::arrayValue);std::uint64_t total=0;bool known=true;
        for(const auto& role:chosen) {
            const auto maximum=std::min(role=="esp"?4*gib:UINT64_MAX,budget-(minima-floors.at(role)));const auto floor=floors.at(role);
            const auto preferred=initial_bytes(role,floor,maximum);
            Value row;row["role"]=role;
            row["unit"]=menu("Unit for "+role,{"GiB","Binary gibibytes","GB","Decimal gigabytes","MiB","Binary mebibytes","MB","Decimal megabytes","%","Percent of original userdata pool"});
            const auto unit=row["unit"].asString();
            auto initial=size_text(preferred,unit,pool,preferred!=maximum,3);
            if(const auto parsed=requested_bytes(initial,unit,pool);!parsed||*parsed<floor||*parsed>maximum)initial=size_text(preferred,unit,pool,false,6);
            row["size"]=input("Size for "+role+" in "+unit+" ("+size_text(floor,unit,pool,true,3)+" - "+size_text(maximum,unit,pool,false,3)+")",initial);
            row["filesystem"]=role=="esp"?"fat32":role=="windows"?"ntfs":role=="linux_swap"?"linux-swap":filesystem(false);
            if(request["advanced"]==true)row["label"]=input("GPT label for "+role+" (unique ASCII identifier, at most 36 characters)",role);
            if(const auto bytes=requested_bytes(row["size"].asString(),unit,pool))total+=*bytes;else known=false;
            partitions.append(row);
        }
        if(!known||total<=budget)break;
        notice("These sizes need "+gib_text(total)+", but only "+gib_text(budget)+" is available after Android keeps its "+gib_text(reserve)+".\n\nEnter smaller sizes.");
    }
    request["partitions"]=partitions;
    if(request["advanced"]==true) {
        std::string initial="userdata";for(const auto& row:partitions)initial+=" "+row["role"].asString();std::string role;
        const auto order=input("Partition ROLE order, separated by spaces. Userdata must be first.",initial);std::istringstream stream(order);request["order"]=Value(Json::arrayValue);while(stream>>role)request["order"].append(role);
    }return request;
}
}
int wizard(bool singleboot,bool dry_run) {
    try {
        need(isatty(STDIN_FILENO)&&isatty(STDOUT_FILENO),"An interactive terminal is required; no unattended erase option exists");
        auto current=inspect();ure::Root system("/");power();native_tool("dialog");native_tool("dmsetup");native_tool("wipefs");
        notice("Only userdata and proven project-created children inside its ORIGINAL extent may change. Other OEM records and payloads remain protected.\n\nBack up your files first. Metadata receipts are not file backups.\n\nExisting carved layouts require the original same-device GPT archive AND a completed creation receipt. Unknown ownership, corrupt GPT or wrong-device evidence cannot be overridden.");
        const fs::path parent=input("Existing root-owned private directory on a separate ext4/XFS USB or other external disk. No part of the affected LUN may hold the journal.");trusted(parent);ure::private_directory(parent,false);journal_identity(parent,current.target);
        const auto job=parent/("uke-layout-"+ure::operation_id());ure::private_directory(job,true);
        const fs::path original=input("Original same-device GPT backup directory. Leave blank ONLY if userdata still has its original uncarved GPT layout.");std::string firmware=profile();
        if(original.empty()) {ure::multiboot_inspect(current.target,{},firmware,&system);backup(current.target,job/"original-gpt",firmware);}
        else {trusted(original);firmware=load_private(original/"manifest.json")["firmware_profile"].asString();need(ure::identifier(firmware),"Invalid original firmware profile");copy_original(original,job/"original-gpt");}
        const auto inspection=ure::multiboot_inspect(current.target,job/"original-gpt",firmware,&system);Value receipt;
        if(inspection["existing_multiboot"]==true){const fs::path path=input("Completed uke-control ownership.json receipt for the current child partitions");trusted(path.parent_path());receipt=load_private(path);require_ownership(inspection,receipt,current.target.identity);save_private(job/"previous-ownership.json",receipt);}
        const bool preserve=menu("Userdata file policy",{"preserve","Preserve the verified filesystem and files","recreate","Erase userdata and create a new Linux filesystem; two approvals"})=="preserve";
        const auto selectedfs=preserve?current.evidence.filesystem:filesystem(true,current.evidence.filesystem);
        auto request=layout_request(singleboot,selectedfs,inspection["pool"]["bytes"].asUInt64());
        auto proposal=propose(system,current.target,request,job/"original-gpt",firmware,receipt,current.evidence,preserve,true);
        bool finish_fastboot=true;
        if(proposal.document["route"]=="direct") {
            finish_fastboot=menu("After successful conversion",{"fastboot","Enter fastboot and flash the matching system image","stay","Stay in Linux"})=="fastboot";
            if(!finish_fastboot)proposal=propose(system,current.target,request,job/"original-gpt",firmware,receipt,current.evidence,preserve,false);
        }
        save_private(job/"plan.json",proposal.document);const auto preview_text=preview(proposal.document);std::cout<<preview_text;
        if(dry_run){notice(preview_text+"\nRead-only preview. No storage write or reboot was prepared.");return 0;}
        if(proposal.document["route"]=="blocked"){notice(preview_text+"\nNo storage change was prepared. To choose erase/recreate, start a fresh wizard and give two explicit approvals. Filesystem failures never select erase automatically.");return 1;}
        if(proposal.document["no_changes_required"]==true){notice("The requested layout and userdata size already match. No write or reboot is needed.");return 0;}
        if(proposal.document["route"]=="shutdown")need(finish_fastboot,"Offline conversion finishes in fastboot; select fastboot in a fresh wizard");
        need(!finish_fastboot||fastboot_available(),"Bound bootloader restart support is unavailable");
        notice(preview_text);if(!yes("Approve this exact layout?\n\n"+preview_text))throw Cancel{};
        unsigned approvals=1;
        if(proposal.document["data_loss"]==true) {
            const auto phrase="ERASE "+proposal.document["sha256"].asString().substr(0,12);
            need(input("FINAL DATA LOSS APPROVAL\n\nExisting project child volumes will be erased. Userdata preservation follows the reviewed plan.\n\nType exactly: "+phrase)==phrase,"Second approval did not match; nothing was prepared");++approvals;
        }
        notice(finish_instructions(proposal.document));Value consent;consent["schema"]="org.uke.control.layout.consent.v1";consent["plan_sha256"]=proposal.document["sha256"];consent["approvals"]=approvals;consent["boot_id_sha256"]=ure::sha256(read("/proc/sys/kernel/random/boot_id"));consent["expires_ms"]=Json::UInt64(boot_ms()+10*60*1000);consent["journal"]=journal_identity(job,current.target);consent["sha256"]=seal(consent);save_private(job/"consent.json",consent);
        power();const bool shutdown=proposal.document["route"]=="shutdown";
        const auto unit="uke-layout-"+proposal.document["sha256"].asString().substr(0,12);
        const auto result=run({native_tool("systemd-run"),"--unit="+unit,"--collect","--wait","--property=Type=exec","--property=UMask=0077","--property=NoNewPrivileges=yes","--property=SendSIGKILL=no","--property=KillMode=process","--property=TimeoutStopSec=infinity","--property=OOMScoreAdjust=-1000","--",native_tool("systemd-inhibit"),"--what=shutdown:sleep","--mode=block","--who=uke-control","--why=Complete confirmed userdata layout operation","/usr/libexec/uke-control/layout-manager",shutdown?"--prepare":"--worker",(job/"consent.json").string(),consent["sha256"].asString()});
        std::cout<<result.output;need(result.status==0,"Layout worker failed. Inspect the external journal; do not retry an already-started job");
        if(shutdown) {
            const auto ready=load_private("/run/initramfs/etc/uke-layout/request.json");
            need(ready["plan_sha256"]==proposal.document["sha256"]&&ready["sha256"]==seal(ready)&&ready["expires_ms"].asUInt64()>=boot_ms(),"The prepared shutdown task does not match the approved plan");
            try{checked({native_tool("systemctl"),"--check-inhibitors=yes","reboot"});}catch(...){withdraw_shutdown(proposal.document["sha256"].asString());throw;}
        }else {
            const auto state=load_private(job/"state.json");need(state["completed"]==true,"Worker did not record verified completion");
            std::cout<<finish_instructions(proposal.document)<<"\nJournal: "<<job<<'\n';
            if(finish_fastboot)checked({native_tool("systemctl"),"--check-inhibitors=yes","reboot","bootloader"});
        }return 0;
    }catch(const Cancel&){std::cout<<"Cancelled. No new storage operation was authorized.\n";return 0;}
}
int command(int argc,char** argv) {
    need(argc>=2,"Expected singleboot or multiboot");const std::string action=argv[1];
    if(action=="--offline"){need(argc==2,"Unexpected offline argument");return offline();}
    if(action=="--worker"||action=="--prepare") {
        need(argc==4&&geteuid()==0,"A private root job request and the exact interactive consent digest are required");const fs::path request=argv[2];
        if(action=="--prepare")prepare_shutdown(request.parent_path(),argv[3]);else run_worker(request,false,argv[3],[](const auto& phase){std::cout<<phase<<std::endl;});return 0;
    }
    need(action=="singleboot"||action=="multiboot","Unknown boot layout command");bool as_json=false,dry=false,status=false;
    for(int i=2;i<argc;++i){const std::string word=argv[i];if(word=="--json")as_json=true;else if(word=="--dry-run")dry=true;else if(word=="status")status=true;else throw cli::UsageError("expected "+action+" [status | --dry-run]");}
    if(status){need(!dry,"Status cannot be combined with an interactive preview");cli::print(ure::json(inspect().summary),as_json);return 0;}
    if(as_json)throw cli::UsageError("--json requires singleboot status or multiboot status; the wizard is interactive");
    return wizard(action=="singleboot",dry);
}
}
#ifndef UKE_LAYOUT_NO_MAIN
int main(int argc,char** argv) {
    try{return uke::layout::command(argc,argv);}catch(const uke::cli::UsageError& error){std::cerr<<"uke-control: "<<error.what()<<'\n';return 64;}catch(const std::exception& error){std::cerr<<"uke-control: "<<error.what()<<'\n';return 1;}
}
#endif

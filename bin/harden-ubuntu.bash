#!/bin/bash
###
### SCRIPTNAME [ options ] a script to harden Ubuntu Operating System
###
###	-h | --help		display this message and exit
###	-d | --debug		run verbosely for debugging purposes
###	-c | --checksum 	checksum script, display it, and exit
###	-v | --verify  		insure that the script ran successfully
###	-i | --install  	run the specific commands required
###
### The script is currently run from: BASEDIR
### The script install files into the following:
###
###	+ INSTALLDIR/cfg -- configuration files for exceptions
###	+ INSTALLDIR/var -- log files and output of specific runs
###	+ INSTALLDIR/bin -- this script and helper functions and code
###

#
# This function takes two inputs, the first a number and then a string.
# The script prints out the string, and then exits with that number
# This can be used to set breakpoints, as well as display errors
#
complain_and_exit () {

  ExitCode=${1:-"0"}
  [ $ExitCode -gt 0 ] && {
    shift
    ExitReason=$@
    echo "ERROR: ${ExitReason}"
    echo "Exiting"
  }
  exit $ExitCode

}

#
# This function display a usage, based on the text at the top of the script
# The function stream the current $0 argument and looks for '###'
# then substitutes specific values before exiting
#

display_help () {

  scriptname=$( basename $0 | cut -d"." -f1 ) 
  startdir=$( ls -Ld $PWD ) 
  installdir="/var/tmp/hardening"
  cat $0 | egrep -i '^###' | sed  's/^###//g' | \
  sed "s/SCRIPTNAME/$scriptname/g" | \
  sed "s#INSTALLDIR#$installdir#g" | \
  sed "s#BASEDIR#$startdir#g" 
  exit 0

}

#
# This is a boilerplate function that sets permissions on file creation
# path, and the executable to use for the checksums, among others. 
# This is where global variables should be set to be used for the script
# If checksumflag is set, the script sums itself, prints the sum, and exits.
#

initialize_variables () {

  ${verboseflag}
  umask 022
  PATH="/usr/bin:/usr/sbin:/bin:/sbin:$PATH"	&& export PATH
  scriptname=$( basename $0 )			&& export scriptname
  base=$( ls -Ld $PWD )				&& export basedir
  installdir="/var/tmp/hardening"		&& export installdir
  bindir=${installdir}/bin			&& export bindir
  vardir=${installdir}/var			&& export vardir
  cfgdir=${installdir}/cfg			&& export cfgdir
  tmpdir="/tmp/hardening"			&& export tmpdir
  datestamp=$( date +%Y%m%d )			&& export datestamp
  timestamp=$( date +%H%M%S )			&& export timstamp
  hostname=$( uname -n)				&& export hostname
  logtag="hardening"				&& export logtag
  logfile="$vardir/$hostname.$logtag.txt"	&& export logfile
  
  for sumexe in sum md5sum sha1sum sha256sum 
  do
    whichresult=$( which $sumexe )
    [ $( echo $whichresult | wc -c ) -gt 1 ] && {
      sumtype=$sumexe
      sumcmd=$whichresult
    }
  done
  
  [ $checksumflag = "true" ] && {
    sumresult=$( $sumcmd $0 | awk '{print$1}' )
    echo "$sumtype:$sumresult"
    exit 0
  }

  sleeptime=$((($RANDOM % 100 + 1) + 20))  && export sleeptime

}

#
# This looks to check if the github can be reached
# Also, it looks to see if it can pull down the script
#
# This only uses a wget, so as to not involve git commands
# afterwards, it unpacks the zip file into a tempoerary directory.
#
# The script compares the temporary file and the running file, and if 
# the checksum differs, installs for the next time. This is done by 
# insuring an at job is installed to run the hardening.
#
download_script () {

  ${verboseflag}
  pingcount=10
  githubsite="www.github.com"
  githubrepo="https://github.com/wayne-kirk-schmidt/DataClearTools/archive/master.zip"
  sleep $sleeptime
  pingresult=$( ping -n -c $pingcount $githubsite 2>/dev/null | egrep -i ttl | wc -l  )
  [ $pingresult -gt 5 ] && {
    targetfile=$( basename $githubrepo )
    [ -d $tmpdir ] && {
      mv $tmpdir $tmpdir.orig
      rm -rf $tmpdir.orig
    }
    mkdir -p $tmpdir
    cd $tmpdir
    rm -f $targetfile
    sudo apt-get install zip unzip
    wget $githubrepo 2>/dev/null
    unzip $targetfile 2>/dev/null 1>&2
  }
}

copy_files () {

  for targetdir in $cfgdir $bindir $vardir
  do
    [ -d $targetdir ] || {
      ExitReason="Unable to make: $targetdir"
      mkdir -p $targetdir || complain_and_exit 101 ${ExitReason}
    }
  done

  [ -d $tmpdir ] && {
    scriptname="harden-ubuntu.bash"
    srcfile=$( find $tmpdir -name $scriptname -print )
    [ -f $srcfile ] && {
      dstfile="$bindir/$scriptname"
      export dstfile
      [ -f $dstfile ] || cp -f $srcfile $dstfile
      [ -f $dstfile ] && { 
        srcsum=$( $sumcmd $srcfile 2>/dev/null | awk '{print$1}' )
        dstsum=$( $sumcmd $dstfile 2>/dev/null | awk '{print$1}' )
        [ $srcsum != $dstsum ] && cp -f $srcfile $dstfile 
      }
    }
    find $tmpdir -name "*.harden" -exec cp {} $cfgdir \;
  }
}

install_at_job () {
  ${verboseflag}
  croncmd="$dstfile"
  cronjob="0 * * * * $dstfile"

  [ $installflag = "true" ] && {
    ( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab -
  }

  [ $verifyflag = "true" ] && {
    checkvalue=$( crontab -l 2>/dev/null | grep -i -F "$croncmd" | wc -c )
    status="uninstalled"
    [ $checkvalue -gt 6 ] && status="installed"
    printf "Security:Cronjob: \t $status\n"
  }

}

#
# Enable UFW, andmake sure the default is no inbound traffic
# Outbound traffic is permitted.
#
# This also installs fail2ban, with defaults which includes ssh
#

turn_on_firewall () {

  ${verboseflag}

  [ $installflag = "true" ] && {
    checkvalue=$( dpkg --list | egrep -i 'ufw|fail2ban' | wc -l )
    [ $checkvalue -lt 2 ] && {
      { 
        sudo apt-get install ufw -y 

        sudo apt-get install fail2ban -y
        sudo systemctl start fail2ban
        sudo systemctl enable fail2ban

        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        sudo ufw logging on

        echo y | sudo ufw enable 

      } 2>$logfile 1>&2
    }
  }

  [ $verifyflag = "true" ] && {
    checkvalue=$( dpkg --list | egrep -i 'ufw|fail2ban' | wc -l )
    status="uninstalled"
    [ $checkvalue -ge 2 ] && status="installed"
    printf "Security:Firewall: \t $status\n"
  }

}

#
# Turn off setuid bits associated with root and executables.
# keep su/sudo/mount/passwd, and strip the rest
#
turn_off_setbits () {

  ${verboseflag}

  fileoutput="/tmp/fileoutput"

  [ $installflag = "true" ] && {
    filelist=""
    for permset in {1,2,3,4,5,6,7}000
    do 
      find / -user root -type f -perm -${permset} -print 2>/dev/null | \
      egrep -v '(sudo|mount|ping)' >> $fileoutput
    done
    filelist=$( cat $fileoutput )
    for file in ${filelist}
    do
      sudo chmod ugo-s $file
      echo "chmod ugo-s $file" 2>$logfile 1>&2
    done
  }

  [ $verifyflag = "true" ] && {
    filelist=""
    for permset in {1,2,3,4,5,6,7}000
    do 
      find / -user root -type f -perm -${permset} -print 2>/dev/null | \
      egrep -v '(sudo|mount|ping)' >> $fileoutput
    done
    checkvalue=$( cat $fileoutput | sort -rbn | wc -l )
    status="uninstalled"
    [ $checkvalue -lt 5 ] && status="installed"
    printf "Security:SetIDFiles: \t $status\n"
  }
  
  rm -f $fileoutput

}

#
# Harden shared memory on the machine
#
secure_shared_memory () {

  ${verboseflag}

  fstab="/etc/fstab"

  [ $installflag = "true" ] && {
    checkvalue=$( cat $fstab | egrep -i shm | egrep -i nosuid | egrep -i noexec | wc -c )
    [ -f $fstab ] && {
      rm -f $fstab.orig
      cp -p $fstab $fstab.orig
      [ $checkvalue -lt 10 ] && {
        sudo echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0" >> $fstab
      }
    }
  }

  [ $verifyflag = "true" ] && {
    checkvalue=$( cat $fstab | egrep -i shm | egrep -i nosuid | egrep -i noexec | wc -c )
    status="uninstalled"
    [ $checkvalue -ge 10 ] && status="installed"
    printf "Security:SharedMem: \t $status\n"
  }
}

#
# Make an admin group, so that we can tie groups to sudo policy
#
make_admin_group () {

  ${verboseflag}

  admgroup="secadm"

  [ $installflag = "true" ] && {
    checkvalue=$( compgen -g | egrep -i $admgroup | wc -l ) 
    [ $checkvalue -lt 1 ] && sudo groupadd $admgroup
  }

  [ $verifyflag = "true" ] && {
    status="uninstalled"
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:AdminGrp: \t $status\n"
  }

}

#
# Install an ssh configuration in addition to the UFW rules
# this disables things such as TCP keepalives, etc.
#
harden_sshd_config () {

  ${verboseflag}

  cfgfilesrc="$cfgdir/sshd_config.harden"
  cfgfiledst="/etc/ssh/sshd_config"
  cfgfilebkp="$cfgdir/sshd_config.master"

  [ $installflag = "true" ] && {
    [ -f $cfgfiledst ] && {
      [ -e $cfgfilebkp ] || cp -p $cfgfiledst $cfgfilebkp
      [ -e $cfgfilesrc ] && {
        checkvalue=$( cat $cfgfiledst | egrep -i HARDENED | wc -l )
        [ $checkvalue -lt 1 ] && {
          sudo cp -p $cfgfilesrc $cfgfiledst
          sudo chmod 644 $cfgfiledst
          sudo service ssh restart
        }
      }
    }
  }

  [ $verifyflag = "true" ] && {
    status="uninstalled"
    checkvalue=$( cat $cfgfiledst | egrep -i HARDENED | wc -l )
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:SShdConfig: \t $status\n"
  }

}

#
# This function hardens the network stack to make things more resistant to attack.
#
harden_sysctl () {

  ${verboseflag}

  cfgfiledst="/etc/sysctl.conf"
  cfgfilesrc="$cfgdir/sysctl.conf.harden"
  cfgfilebkp="$cfgdir/sysctl.conf.master"

  [ $installflag = "true" ] && {
    [ -f $cfgfiledst ] && {
      [ ! -f $cfgfilebkp ] && cp -p $cfgfiledst $cfgfilebkp
      [ -f $cfgfilesrc ] && {
        checkvalue=$( cat $cfgfiledst | egrep -i HARDENED | wc -l )
        [ $checkvalue -lt 1 ] && {
          sudo cat $cfgfilesrc >> $cfgfiledst
          sudo chmod 644 $cfgfiledst
          sudo sysctl -p
        }
      }
    }
  }

  [ $verifyflag = "true" ] && {
    status="uninstalled"
    checkvalue=$( cat $cfgfiledst | egrep -i HARDENED | wc -l )
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:SysctlCfg: \t $status\n"
  }

}

prevent_ip_spoofing () {

  ${verboseflag}
  cfgfiledst="/etc/host.conf"

  [ $installflag = "true" ] && {
    checkvalue=$( cat $cfgfiledst | egrep -i spoof | egrep -i no | wc -l )
    [ $checkvalue -lt 1 ] && {
      sudo echo "nospoof on" >> $cfgfiledst
    }
  }

  [ $verifyflag = "true" ] && {
    status="uninstalled"
    checkvalue=$( cat $cfgfiledst | egrep -i spoof | egrep -i no | wc -l )
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:NoIPSpoof: \t $status\n"
  }

}

#
# This sets up the default app_armor for a server
#
setup_app_armor () {

  ${verboseflag}

  [ $installflag = "true" ] && {
    checkvalue=$( dpkg --list | egrep -i 'apparmor' | wc -l )
    [ $checkvalue -lt 1 ] && {
      {
        sudo apt-get install apparmor apparmor-profiles -y
      } 2>$logfile 1>&2
    }
  }

  [ $verifyflag = "true" ] && {
    status="uninstalled"
    checkvalue=$( dpkg --list | egrep -i 'apparmor' | wc -l )
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:AppArmor: \t $status\n"
  }

}

#
# This sets up and runs root kit checks
#
setup_rootkit_checks () {

  ${verboseflag}

  [ $installflag = "true" ] && {
    checkvalue=$( dpkg --list | egrep -i 'chkrootkit' | wc -l )
    [ $checkvalue -lt 1 ] && {
      {
        sudo apt-get install chkrootkit -y
        sudo chkrootkit
      } 2>$logfile 1>&2
    }
  }
  [ $verifyflag = "true" ] && {
    status="uninstalled"
    checkvalue=$( dpkg --list | egrep -i 'chkrootkit' | wc -l )
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:Chkrootkit: \t $status\n"
  }

  [ $installflag = "true" ] && {
    checkvalue=$( dpkg --list | egrep -i 'rkhunter' | wc -l )
    [ $checkvalue -lt 1 ] && {
      {
        sudo apt-get install binutils libreadline5 libruby ruby ruby ssl-cert unhide.rb mailutils
        sudo apt-get install rkhunter -y
        sudo rkhunter --update
        sudo rkhunter --propupd
        sudo rkhunter --check
        sudo rkhunter --check --sk
      } 2>$logfile 1>&2
    }
  }
  [ $verifyflag = "true" ] && {
    status="uninstalled"
    checkvalue=$( dpkg --list | egrep -i 'rkhunter' | wc -l )
    [ $checkvalue -ge 1 ] && status="installed"
    printf "Security:RKhunter: \t $status\n"
  }

}

harden_host () {

  ${verboseflag}

  install_at_job
  turn_on_firewall
  turn_off_setbits
  secure_shared_memory
  make_admin_group
  harden_sshd_config
  harden_sysctl
  prevent_ip_spoofing
  setup_app_armor
  setup_rootkit_checks

}

initialize_options () { 

  verboseflag=""
  checksumflag="false"
  installflag="false"
  verifyflag="false"

}

main_logic () { 

  initialize_variables

  [ $installflag = "true" ] && {
    download_script
    copy_files
  }

  harden_host

}

initialize_options
  
while getopts "hdcvi" options;
do
  case "${options}" in
    h) display_help		; exit 0 ;;
    d) verboseflag='set -x'	; export verboseflag ;;
    c) checksumflag=true	; export checksumflag ;;
    v) verifyflag=true		; export verifyflag ;;
    i) installflag=true		; export installflag ;;
    *) display_help		; exit 0 ;;
  esac
done
shift $((OPTIND-1))

main_logic

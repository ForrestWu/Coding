#
# vi:set ts=4
#
# Author: Forrest Wu (junchao.wu@gmail.com)
#

#
# Public library to configure rsh auto login without password. 
#

################################################################################
#                                                                              #
#                           private functions                                  #
#                                                                              #
################################################################################

#
# POSIX function is equal to macro in C
#
__rsh_debug()
{
        __RSH_DEBUG=$(print "$__RSH_DEBUG"  | sed -e 's/,/|/g')

        eval [[ $1 == "+($__RSH_DEBUG)" ]] || [[ $__RSH_DEBUG == all ]] && \
                PS4='[${.sh.file##*/}:${.sh.fun}:$LINENO|${SECONDS%.*}]+ ' && \
                set -x
}

#
# ssh with nis user/passwd, then update rsh access configuration with root.
#
function __rsh_update_config
{
        __rsh_debug $0

        typeset host=${1?}
        typeset nis_user=${2?}
        typeset nis_passwd=${3?}
        typeset root_passwd=${4?}

        typeset update_config=$(mktemp /tmp/update_config.XXXXX.exp)
        [[ -n $update_config ]] || return 2
        trap "rm -f $update_config " EXIT

        cat > $update_config <<- EOF
        #!/usr/bin/expect

        set timeout     90

        spawn ssh -o StrictHostKeyChecking=no -F /dev/null -l $nis_user $host
        expect {
                "continue connecting (yes/no)? " {
                        send "yes\r" 
                        sleep 1
                        expect "Password: "
                        send "$nis_passwd\r"
                } "Password: " {
                        send "$nis_passwd\r"
                } "Connection refused" {
                        puts "*** sshd not running?"
                        exit 1
                } "Last login*" {
                        send "\r"
                        puts "*** succeed to ssh without password."
                } timeout {
                        puts "*** Time out"
                        exit 1
                }
        }
        
        #
        # First of all, change user home shell to bash.
        # Otherwise, some user home shell cannot recognize PS1, for example csh.
        #
        expect {
                -re "$|#|>|%" {
                        send "bash\r"
                        sleep 1
                } "Password: " {
                        send "\r"
                        puts "*** Wrong nis-user/password?"
                        exit 1
                } timeout {
                        puts "*** Time out"
                        exit 1
                }
        }
        
        #
        # Then, set PS1 to avoid unexpected prompt in test machine.
        # Disable clear to keep output on the screen after ssh session ended.
        #
        set ps1    "(update_config.exp)# "
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } -re "$|#|>|%" {
                        send "PS1='\$ps1' ; alias clear=''\r"
                        sleep 1
                } timeout {
                        puts "*** Time out"
                        exit 1
                }
        }
        
        #
        # Comment CONSOLE in /etc/default/login
        #
        set login       "/tmp/login.ipoib"
        set sshd_config "/tmp/sshd_config.ipoib"
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } "\$ps1" {
                        send "sed 's/^CONSOLE/#CONSOLE/' \
                                /etc/default/login > \$login \r"
                        send "sed 's/^PermitRootLogin .*$/PermitRootLogin yes/'\
                                /etc/ssh/sshd_config > \$sshd_config \r"
                        sleep 1
                }
        }
        
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } "\$ps1" {
                        send "su root -c \" \
                                cp -f \$login /etc/default/login ;   \
                                cp \$sshd_config /etc/ssh/sshd_config ;   \
                                svcadm restart svc:/network/ssh:default ; \
                                rm -rf \$login \$sshd_config;             \
                                \"\r"
                }
        }
        
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } "Password: " {
                        send "$root_passwd\r"
                        sleep 1
                }
        }
        
        #
        # All operation in remote machine completed, exit bash. 
        #
        set timeout 30
        expect {
                "\$ps1" {
                        send "exit 0\r"
                        sleep 1
                }
        }
        
        #
        # Then, exit user shell
        #
        expect {
                -re "$|#|>|%" {
                        send "exit 0\r"
                        sleep 1
                }
        }
        
        expect eof
        exit 0
EOF

        expect -f $update_config
        return $?
}

#
# Enable rsh access without password required.
#
function __rsh_enable_auto_login
{
        __rsh_debug $0

        typeset user=${1?}
        typeset host=${2?}
        typeset root_passwd=${3?}

        typeset enable_auto_login=$(mktemp /tmp/enable_auto_login.XXXXX.exp)
        [[ -n $enable_auto_login ]] || return 2
        trap "rm -f $enable_auto_login " EXIT

        cat > $enable_auto_login <<- EOF
        #!/usr/bin/expect

        set timeout 90

        spawn ssh -o StrictHostKeyChecking=no -F /dev/null -l root $host
        expect {
                "continue connecting (yes/no)? " {
                        send "yes\r" 
                        sleep 1
                        expect "Password: "
                        send "$root_passwd\r"
                } "Password: " {
                        send "$root_passwd\r"
                } "Connection refused" {
                        puts "*** sshd not running?"
                        exit 1
                } "Last login*" {
                        send "\r"
                        puts "*** succeed to ssh without password."
                } timeout {
                        puts "*** Time out"
                        exit 1
                }
        }
        
        #
        # First of all, change some user home shell to bash.
        # Otherwise, some shell cannot recognize PS1, for example csh.
        #
        expect {
                -re "'\$'|#|>|%" {
                        send "bash\r"
                        sleep 1
                } "Password: " {
                        puts "\n*** Wrong root password or root ssh disabled?"
                        puts "Try to rerun with <nis-account> <nis-password>'\n"
                        exit 1
                } timeout {
                        puts "*** Time out"
                        exit 1
                }
        }
        
        #
        # Then, set PS1 to avoid unexpected prompt in test machine.
        # Disable clear to keep output on the screen after ssh session ended.
        #
        set ps1     "(enable_auto_login.exp)# "
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } -re "$|#|>|%" {
                        send "PS1='\$ps1' ; alias clear=''\r"
                        sleep 1
                } timeout {
                        puts "*** Time out"
                        exit 1
                }
        }
        expect {
                -re "Connection to .* closed." {
                exit 1
                } "\$ps1" {
                        send "su $user -c 'echo + + > ~$user/.rhosts'\r"
                        send "svcadm enable svc:/network/login:rlogin\r"
                        send "svcadm enable svc:/network/shell:default\r"
                        sleep 1
                }
        }
        
        #
        # All operation in remote machine completed. exit 0
        #
        set timeout 30
        expect {
                "\$ps1" {
                        send "exit 0\r"
                        sleep 1
                }
        }
        
        #
        # Then, exit user shell
        #
        expect {
                -re "$|#|>|%" {
                        send "exit 0\r"
                        sleep 1
                }
        }
        
        expect eof
        exit 0
EOF

        expect -f $enable_auto_login
        return $?
}

################################################################################
#                                                                              #
#                           public functions                                   #
#                                                                              #
################################################################################

#
# Setup the specified user rsh access between $sut without password required.
#
# rsh_setup [<-u nis_user> <-p nis_passwd>] 
#       <user> <sut[,sut[,...]]> [root_passwd]
#
#       -u : your nis account
#       -p : your nis account password
#
function rsh_setup
{
        __rsh_debug $0

        typeset -r option="u:p:"
        typeset opt nis_user nis_passwd root_passwd
        while getopts $option opt ; do
                case $opt in
                        u) nis_user=$OPTARG ;;
                        p) nis_passwd=$OPTARG ;;
                        *) return 1 ;;
                esac
        done
        shift $((OPTIND - 1))

        typeset user=${1?"user name required"}
        typeset sut=${2?"SUTs required"}
        typeset root_passwd=${3:-"l1admin"}

        if [[ $(id -u) != 0 ]] ; then
                print -u2 "ERROR: rsh_setup must be run by 'root'"
                return 1
        fi

        #
        # define library internal public variable to shared between different
        # function in librsh.ksh
        #
        __RSH_USER=$user

        #
        # Add master test machine to SUTs list and remove the duplicated items.
        #
        sut=$(print $(hostname),$sut | tr , '\n' | sort -u)

        typeset host
        typeset -i ret
        for host in $sut ; do
                rsh -l $user $host true > /dev/null 2>&1
                (($? == 0)) && continue

                #
                # Once rsh failed, try to enable rsh without password direcotly.
                #
                __rsh_enable_auto_login $user $host $root_passwd
                (($? == 0)) && continue

                if [[ -z $nis_user || -z $nis_passwd ]]; then
                        print -u2 "ERROR: try to rerun with nis account/passwd"
                        return 1
                fi

                #
                # Try to update rsh configuration.
                #
                __rsh_update_config $host $nis_user $nis_passwd $root_passwd
                if (($? != 0)) ; then
                        print -u2 "ERROR: fail to update rsh configuration"
                        return 1
                fi

                #
                # Then, retry again.
                #
                __rsh_enable_auto_login $user $host $root_passwd
                if (($? != 0)); then
                        print -u2 "ERROR: fail to enable rsh auto login"
                        return 1
                fi
        done

        return 0
}

#
# Identify who is using to access remote host via rsh.
#
function rsh_identify
{
        __rsh_debug $0

        typeset user=${1?"user name required"}        

        if ! id $user > /dev/null ; then
                print -u2 "ERROR: cannot get user $user"
                return 1
        fi
        __RSH_USER=$user

        return 0
}

#
# For the specified SUTs, verify $user can access without password required.
#
# rsh_verify_auto_login <user> <sut[,sut[,...]]>
#
function rsh_verify_auto_login
{
        __rsh_debug $0

        typeset sut=${@?"at least one SUT required"}

        # Separate SUT from each other and remove the duplicated items.
        sut="$(print $sut | tr , '\n' | sort -u)"

        typeset host
        for host in $sut ; do
                rsh -l $__RSH_USER $host true > /dev/null 2>&1
                if (($? != 0)); then
                        print -u2 "ERROR: " \
                                "'rsh -l $__RSH_USER $host true' failed."
                        return 1
                fi
        done

        return 0
}

#
# NOTE : rsh_do is a wrapper of function RSH which resides in SUNWstc-genutils.
#       RSH_STC_GENUTILS must be define before call rsh_do
#
# rsh_do [-q] <sut> <command line>
#
function rsh_do
{
        __rsh_debug $0

        typeset option quiet
        while getopts "q" option ; do
                case $option in
                        q) quiet='yes' ;;
                        *) return 1 ;;
                esac
        done
        shift $((OPTIND-1))

        typeset sut=${1?"SUT required!"}
        shift 1
        typeset rcmd=${@?"remote command line required"}

        typeset outlog=$(mktemp /tmp/outlog.$sut.XXXXX)
        typeset errlog=$(mktemp /tmp/errlog.$sut.XXXXX)
        trap "rm -rf $outlog $errlog" EXIT

        #
        # Define unique stamp as keyword to identify rsh
        # execution return value in errlog.
        #
        typeset stamp="STAMP:$(date +"%s.%N").$RANDOM,RETURN:"

        #
        # Execute rsh command and output return value with
        # unique stamp to errlog.
        #
        /usr/bin/rsh -n -l $__RSH_USER $sut /usr/bin/ksh -c \
                "'$rcmd ; print -u2 ${stamp}\$?'" >$outlog 2>$errlog
        typeset ret=$?

        #
        # If rsh itself fails, for example permission deny, just return.
        #
        if [[ $ret != 0 ]] ; then
                [[ -s $outlog ]] && cat $outlog
                [[ -s $errlog ]] && cat $errlog >&2
                print -u2 "ERROR: rsh failed, return = $ret"
                return $ret
        fi

        #
        # figure out return value from errlog
        #
        ret=$(grep "^$stamp" $errlog)
        ret=${ret#$stamp}

        #
        # If call rsh_do as quit mode, just return. Otherwise,
        # output stdout and stderr.
        #
        if [[ -n $quiet ]]; then
                return $ret
        fi

        [[ -s $outlog ]] && cat $outlog
        grep -v "^$stamp" $errlog > $outlog
        [[ -s $outlog ]] && cat $outlog >&2

        return $ret
} 

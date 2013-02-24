#
# vi:set ts=4
#
# Author: Forrest Wu (junchao.wu@gmail.com)
#

#
# Public library to configure ssh auto login without password. Also create the
# wrapper of ssh.
#
# This library provide those external functions to user. The others are internal
# functions, althrough they are in global name space.
#
# ssh_setup
# ssh_identify
# ssh_verify_auto_login
# ssh_do
#

#
# To debug function in libssh.ksh, export __SSH_DEBUG=<function_name|all>
# in your script.
#

################################################################################
#                                                                              #
#                           private functions                                  #
#                                                                              #
################################################################################

#
# POSIX function is equal to macro in C
#
__ssh_debug()
{
        __SSH_DEBUG=$(print "$__SSH_DEBUG"  | sed -e 's/,/|/g')

        eval [[ $1 == "+($__SSH_DEBUG)" ]] || [[ $__SSH_DEBUG == all ]] && \
                PS4='[${.sh.file##*/}:${.sh.fun}:$LINENO|${SECONDS%.*}]+ ' && \
                set -x
}

#
# check if the specified host is accessable for given user
#
function __ssh_is_accessable
{
        __ssh_debug $0

        typeset host=${2?}
        typeset root_passwd=${3?}

        typeset is_accessable_exp=$(mktemp /tmp/is_accessable.XXXXX.exp)
        [[ -n $is_accessable_exp ]] || return 2
        trap "rm -f $is_accessable_exp " EXIT

        cat > $is_accessable_exp <<- EOF
        #!/usr/bin/expect

        set timeout     90
        spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
                -l root $host
        expect {
                "continue connecting (yes/no)? " {
                        send "yes\r" 
                        sleep 1
                        expect "Password: "
                        send "$root_passwd\r"
                } "Password: " {
                        send "$root_passwd\r"
                } "Last login*" {
                        send "exit 0\r"
                        expect eof
                        exit 0
                } "Connection refused" {
                        puts "*** sshd not running?"
                        exit 2
                } "Permission denied*" {
                        puts "*** wrong root password?"
                        exit 2
                } timeout {
                        puts "*** Time out"
                        exit 2
                }
        }
        expect {
                -re "'\$'|#|>|%" {
                        send "exit 0\r"
                } "Password: " {
                        puts "*** root not allow to access?"
                        exit 1
                } "Last login*" {
                        send "exit 0\r"
                } timeout {
                        puts "*** Time out"
                        exit 2
                }
        }
        
        expect eof
        exit 0
EOF

        expect -f $is_accessable_exp
        return $?
}

#
# Update ssh configuration file and enable ssh service.
#
function __ssh_allow_access
{
        __ssh_debug $0

        typeset host=${1?}
        typeset nis_user=${2?}
        typeset nis_passwd=${3?}
        typeset root_passwd=${4?}

        typeset allow_access_exp=$(mktemp /tmp/allow_access.XXXXX.exp)
        [[ -n $allow_access_exp ]] || return 1
        trap "rm -f $allow_access_exp " EXIT

        cat > $allow_access_exp <<- EOF
        #!/usr/bin/expect

        set timeout     90
        spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
                -l $nis_user $host
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
                        exit 2
                } "Permission denied*" {
                        puts "*** $nis_user: Unknown nis user in $host"
                        exit 2
                } timeout {
                        puts "*** Time out"
                        exit 2
                }
        }
        
        sleep 5
        #
        # First of all, change user home shell to bash.
        # Otherwise, some shell cannot recognize PS1, for example csh.
        #
        expect {
                -re "$|#|>|%" {
                        send "bash\r"
                        sleep 1
                } "Password:" {
                        send "\r"
                        puts "*** Wrong nis-user/password ?"
                        exit 1
                } timeout {
                        puts "*** Time out"
                        exit 2
                }
        }

        #
        # Then, set PS1 to avoid unexpected prompt in test machine.
        # Disable clear to keep output on the screen after ssh session ended.
        #
        set ps1    "(allow_access.exp)# "
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
        # Comment PermitRootLogin in /etc/ssh/sshd_config and restart sshd.
        #
        set sshd_config "/tmp/sshd_config.cti"
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } "\$ps1" {
                        send "sed 's/^PermitRootLogin .*$/PermitRootLogin yes/' \\
                                /etc/ssh/sshd_config > \$sshd_config \r"
                        sleep 1
                }
        }
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } "\$ps1" {
                        send "su root -c \" \
                                cp \$sshd_config /etc/ssh/sshd_config ;   \
                                svcadm restart svc:/network/ssh:default ; \
                                rm -rf \$sshd_config ;                    \
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
                "Sorry" {
                        puts "*** Wrong root password."
                        exit 1
                } "\$ps1" {
                        send "exit 0\r"
                        sleep 1
                }
        }

        #
        # Then, exit host.
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

        expect -f $allow_access_exp
        return $?
}

#
# Putting $__SSH_MASTER_PUBKEY_STR into $host:__SSH_KEY_AUTH, so that ssh
# from master no password required.
#
function __ssh_enable_auto_login
{
        __ssh_debug $0

        typeset user=${1?}
        typeset host=${2?}
        typeset root_passwd=${3?}

        #
        # If the target host is the master itself, just put
        # __SSH_MASTER_PUBKEY_STR into $__SSH_KEY_AUTH.
        #
        if [[ $(hostname) == $host ]] ; then
                su $user -c "echo $__SSH_MASTER_PUBKEY_STR >> $__SSH_KEY_AUTH"
                return 0
        fi

        typeset enable_auto_login_exp=$(mktemp /tmp/enable_auto_login.XXXXX.exp)
        [[ -n $enable_auto_login_exp ]] || return 1
        trap "rm -f $enable_auto_login_exp" EXIT

        cat > $enable_auto_login_exp <<- EOF
        #!/usr/bin/expect

        set timeout     90
        spawn ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
                -l root $host
        expect {
                "continue connecting (yes/no)? " {
                        send "yes\r" 
                        sleep 1
                        expect "Password: "
                        send "$root_passwd\r"
                } "Password: " {
                        send "$root_passwd\r"
                } "Last login*" {
                        send "\r"
                } "Connection refused" {
                        puts "*** sshd not running?"
                        exit 2
                } "Permission denied*" {
                        puts "*** $user: Unknown user in $host"
                        exit 2
                } timeout {
                        puts "*** Time out"
                        exit 2
                }
        }
        
        #
        # First of all, change user home shell to bash.
        # Otherwise, some shell cannot recognize PS1, for example csh.
        #
        expect {
                "Password:" {
                        puts "*** Wrong user/password ?"
                        exit 1
                } -re "$|#|>|%" {
                        send "su - $user ; bash\r"
                        sleep 1
                } timeout {
                        puts "*** Time out"
                        exit 2
                }
        }

        #
        # Then, set PS1 to avoid unexpected prompt in test machine.
        # Disable clear to keep output on the screen after ssh session ended.
        #
        set ps1    "(enable_auto_login.exp)# "
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
        # Put master __SSH_MASTER_PUBKEY_STR to host:__SSH_KEY_AUTH
        #
        expect {
                -re "Connection to .* closed." {
                        exit 1
                } "\$ps1" {
                        send "mkdir -p -m 700 $__SSH_KEY_DIR ;  \
                                echo $__SSH_MASTER_PUBKEY_STR >> $__SSH_KEY_AUTH ;\
                                \r"
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
        # Then, exit "su - $user".
        #
        expect {
                -re "$|#|>|%" {
                        send "exit 0\r"
                        sleep 1
                }
        }

        #
        # finally, exit host.
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

        expect -f $enable_auto_login_exp
        return $?
}

#
# Login each host and generate ssh pubkey, then collect and put them into
# $__SSH_KEY_AUTH in each host.
#
function __ssh_generate_pubkey
{
        __ssh_debug $0

        typeset host=${1?}

        #
        # If the target host is the master itself, ignore it since its public
        # key content has been put into $__SSH_KEY_AUTH in each hosts in
        # function __ssh_enable_auto_login.
        #
        [[ $(hostname) == $host ]] && return 0

        #
        # For the others, login and generate ssh public key.
        #
        ssh_do $host "mkdir -p -m 700 $__SSH_KEY_DIR" || return 1
        ssh_do $host "test -f $__SSH_KEY_PRIV"
        if (($? == 0)); then
                ssh_do $host "rm -f $__SSH_KEY_PRIV" || return 1
        fi

        ssh_do $host "ssh-keygen -q -t rsa -N '' -f $__SSH_KEY_PRIV" || return 1

        #
        # Now, put its public key into $__SSH_OTHERS_PUBKEY
        #
        ssh_do $host "cat $__SSH_KEY_PRIV.pub" >> $__SSH_OTHERS_PUBKEY || \
                return 1
}

#
# Append $__SSH_OTHERS_PUBKEY to $__SSH_KEY_AUTH in specified host.
#
function __ssh_deploy_pubkey
{
        __ssh_debug $0

        typeset host=${1?}

        cat $__SSH_OTHERS_PUBKEY | ssh_do $host "cat >> $__SSH_KEY_AUTH"
        return $?
}

################################################################################
#                                                                              #
#                           public functions                                   #
#                                                                              #
################################################################################

#
# Setup the specified user ssh access between $sut without password required.
#
# ssh_setup  [-i identify] [<-u nis_user> <-p nis_passwd>]
#               sut:user:passwd [sut:user:passwd [...]]
# 
#       -i : identify for RSA authentication
#       -u : your nis account
#       -p : your nis account password
#
function ssh_setup
{
        __ssh_debug $0

        typeset -r option="i:u:p:"
        typeset opt identify nis_user nis_passwd root_passwd
        while getopts $option opt ; do
                case $opt in
                        i) identify=$OPTARG ;;
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
                print -u2 "ERROR: ssh_setup must be run by 'root'"
                return 1
        fi

        #
        # If no specified key file, set 'id_rsa' as default value.
        #
        typeset rsa=id_rsa
        [[ -n $identify ]] && rsa=${identify}_id_rsa

        #
        # We assume the same user has same home directory in all involved SUTs.
        # Check the specified user is existing. 
        #
        id $user > /dev/null || return 1
        typeset home=$(grep "^$user:" /etc/passwd | awk -F: '{print $6}')
        if [[ -z $home ]] ; then
                print -u2 "ERROR: cannot found $user home directory"
                return 1
        fi

        __SSH_USER=$user
        __SSH_KEY_DIR=$home/.ssh
        __SSH_KEY_PRIV=$__SSH_KEY_DIR/$rsa
        __SSH_KEY_AUTH=$__SSH_KEY_DIR/authorized_keys

        #
        # Add master test machine to SUTs list and remove the duplicated items.
        #
        sut=$(print $(hostname),$sut | tr , '\n' | sort -u)

        #
        # Force create $__SSH_KEY_PRIV key which is used to put on all host
        # and make ssh access from master without password required.
        #
        su $__SSH_USER -c "mkdir -p -m 700 $__SSH_KEY_DIR" || return 2
        if [[ -f $__SSH_KEY_PRIV ]] ; then
                su $__SSH_USER -c "rm -f $__SSH_KEY_PRIV" || return 2
        fi
        su $__SSH_USER -c \
                "ssh-keygen -q -t rsa -N '' -f $__SSH_KEY_PRIV" || return 1
        __SSH_MASTER_PUBKEY_STR=$(cat ${__SSH_KEY_PRIV}.pub)

        typeset host
        typeset -i ret
        for host in $sut ; do
                #
                # check if the remote host can be acessable via ssh
                #
                __ssh_is_accessable $user $host $root_passwd
                ret=$?

                #
                # Unresolved issues or unknow error, need resolve manually.
                #
                if (($ret == 2)) ; then
                        print -u2 "ERROR: Unresolved issues." \
                                "Please resolve it manually."
                        return 1
                fi

                #
                # Failed to login due to configuration setting, update
                # /etc/ssh/ssh_config via login with nis user
                #
                if (($ret == 1)) ; then
                        if [[ -z $nis_user || -z $nis_passwd || \
                                -z $root_passwd ]];
                        then
                                print -u2 "ERROR: please try to re-run with" \
                                        "nis account and password."
                                return 1
                        fi

                        __ssh_allow_access $host $nis_user $nis_passwd \
                                $root_passwd || return 1
                fi

                #
                # Put master $__SSH_MASTER_PUBKEY_STR to all machines, so ssh
                # access from master system without password required.
                #
                __ssh_enable_auto_login $user $host $root_passwd || return 1
        done

        #
        # Generate public key in each hosts and put them into file
        # $__SSH_OTHERS_PUBKEY.
        #
        __SSH_OTHERS_PUBKEY=$(mktemp /tmp/others_pubkey.XXXXX)
        trap "rm -f $__SSH_OTHERS_PUBKEY" EXIT
        for host in $sut ; do
                __ssh_generate_pubkey $host || return 1
        done

        #
        # Generate ssh private key in each host separately, then collect and
        # deploy ssh public key to each host.
        #
        for host in $sut ; do
                __ssh_deploy_pubkey $host || return 1
        done

        return 0
}

#
# Identify which user and rsa are using ssh login the remote machine.
# If identify is not specified, the default file is id_rsa.
#
# ssh_identify <user> [identify]
#
function ssh_identify
{
        __ssh_debug $0

        typeset user=${1?"user name required"}
        typeset identify=$2

        id $user > /dev/null || return 1
        typeset home=$(grep "^$user:" /etc/passwd | awk -F: '{print $6}')
        [[ -n $home ]] || return 1
        __SSH_USER=$user

        typeset rsa=id_rsa
        [[ -n $identify ]] && rsa=${identify}_id_rsa
        __SSH_KEY_PRIV=$home/.ssh/$rsa

        return 0
}

#
# For the given hosts, verify they can access with each other no password
# required.
#
# ssh_verify_auto_login <SUT1[,SUT2[,...]]>
#
function ssh_verify_auto_login
{
        __ssh_debug $0

        typeset sut=${@?"At least one SUT required!!!"}

        if [[ -z $__SSH_KEY_PRIV ]] ; then
                print -u2 "ERROR: please call ssh_identify firstly"
                return 1
        fi
        if [[ ! -f $__SSH_KEY_PRIV ]] ; then
                print -u2 "ERROR: make sure the specified rsa has been created"
                return 1
        fi

        # Separate SUT from each other and remove the duplicated items.
        sut="$(print $sut | tr , '\n' | sort -u)"

        typeset host host2
        for host in $sut ; do
                for host2 in $sut ; do
                        ssh_do $host ssh -i $__SSH_KEY_PRIV \
                                -o StrictHostKeyChecking=no -o BatchMode=yes \
                                $host2 true < /dev/null || return 1
                done
        done

        return 0
}

#
# Wrapper of ssh to simplify ssh access without password required.
# Typically, there are two kind of methods to use ssh_do.
#
# ssh_do [-q] <sut> <command line>
#
# 1. single line mode
# 
#       ssh_do speedball "hostname" || return 1
#       ssh_do -q speedball "ls -ld /tmp" || return 2
# 
# 2. multiple lines mode
#
#       ssh_do speedball <<- EOF
#               hostname || return 1
#               ls -ld /tmp || return 2
#       EOF
#
function ssh_do
{
        __ssh_debug $0

        typeset option quiet
        while getopts "q" option ; do
                case $option in
                        q) quiet='yes' ;;
                        *) return 1 ;;
                esac
        done
        shift $((OPTIND-1))

        typeset sut=${1?"SUT required!"}
        shift

        if [[ -z $__SSH_USER || -z $__SSH_KEY_PRIV ]] ; then
                print -u2 "ERROR: please call ssh_identify firstly"
                return 1
        fi
        if [[ ! -f $__SSH_KEY_PRIV ]] ; then
                print -u2 "ERROR: make sure the specified rsa has been created"
                return 1
        fi

        typeset sshcmd="ssh -i $__SSH_KEY_PRIV -o StrictHostKeyChecking=no"
        sshcmd="$sshcmd -o BatchMode=yes -l $__SSH_USER $sut"

        if [[ -n $quiet ]]; then
                $sshcmd "$@" > /dev/null
        else
                $sshcmd "$@"
        fi
}

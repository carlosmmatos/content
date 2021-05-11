#!/bin/bash

SSH_PORT=22222

for test in sshd_allow_only_protocol2 sshd_rekey_limit selinux_state coredump_disable_backtraces accounts_tmout coredump_disable_storage sshd_set_idle_timeout accounts_have_homedir_login_defs sshd_set_max_sessions configure_openssl_tls_crypto_policy selinux_policytype selinux_policytype configure_tmux_lock_after_time sshd_disable_compression sshd_set_max_auth_tries configure_tmux_lock_command
do
    nohup ./test_rule_in_container.sh --dontclean --ssh-port ${SSH_PORT} -r ansible ${test} > nohup.${test} 2>&1 &
    ((SSH_PORT++))
    sleep 1
done


# ./test_rule_in_container.sh --dontclean --ssh-port=22211 --remediate-using ansible sshd_allow_only_protocol2
# ./test_rule_in_container.sh --dontclean --ssh-port=22212 --remediate-using ansible sshd_rekey_limit
# ./test_rule_in_container.sh --dontclean --ssh-port=22213 --remediate-using ansible selinux_state
# ./test_rule_in_container.sh --dontclean --ssh-port=22214 --remediate-using ansible coredump_disable_backtraces
# ./test_rule_in_container.sh --dontclean --ssh-port=22215 --remediate-using ansible accounts_tmout
# ./test_rule_in_container.sh --dontclean --ssh-port=22216 --remediate-using ansible coredump_disable_storage
# ./test_rule_in_container.sh --dontclean --ssh-port=22217 --remediate-using ansible sshd_set_idle_timeout
# ./test_rule_in_container.sh --dontclean --ssh-port=22218 --remediate-using ansible accounts_have_homedir_login_defs
# ./test_rule_in_container.sh --dontclean --ssh-port=22219 --remediate-using ansible sshd_set_max_sessions
# ./test_rule_in_container.sh --dontclean --ssh-port=22220 --remediate-using ansible configure_openssl_tls_crypto_policy
# ./test_rule_in_container.sh --dontclean --ssh-port=22221 --remediate-using ansible selinux_policytype
# ./test_rule_in_container.sh --dontclean --ssh-port=22222 --remediate-using ansible configure_tmux_lock_after_time
# ./test_rule_in_container.sh --dontclean --ssh-port=22223 --remediate-using ansible sshd_disable_compression
# ./test_rule_in_container.sh --dontclean --ssh-port=22224 --remediate-using ansible sshd_set_max_auth_tries
# ./test_rule_in_container.sh --dontclean --ssh-port=22225 --remediate-using ansible configure_tmux_lock_command

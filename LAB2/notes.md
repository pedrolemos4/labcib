docker save -o img.tar isepdei/insecurelabs02
usar o dive para descobrir em que layer o .env é apagado
editar manifest.json para remover referencias ao hash correspondente a layer onde o .env é apagado
ir ao blobs/sha256, procurar referencias a esse hash, e remover
tar -czvf inseclab2mod.tar blobs/ index.json manifest.json oci-layout repositories
docker load -i inseclab2mod.tar
docker run, exec shell e ler
https://www.gasparevitta.com/posts/advanced-docker-secrets-buildkit/
Advanced Docker: how to use secrets the right way
Secrets are the sneakier vulnerability issue in Docker if you don't know how to handle them. In this tutorial I'll explain how to use a build secret safely
Advanced Docker: how to use secrets the right way


6. funciona igual (dá para pingar): sudo setcap -r /usr/bin/ping
 
sudo sysctl -w net.ipv4.ping_group_range="0 0"
isto faz com qe o ping deixe de funcionar sem a capability
para restaurar o normal: sudo sysctl -w net.ipv4.ping_group_range="0 2147483647" 

para testar
setcap -r /usr/bin/ping
getcap /usr/bin/ping
ping 1.1.1.1 ---------------> nao faz nada

repor:

setcap 'cap_net_raw=ep' /usr/bin/ping

==========================================================================================

CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000


0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap


Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_module,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: HYBRID (4)




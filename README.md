In April 2019, SAP Gateway and Message server security became talk of the town. Malicious cyber actors can attack and compromise SAP unsecure systems (Systems without proper message server and Gateway ACLs and required parameters) with publicly available exploit tools, termed "10KBLAZE". Read https://www.us-cert.gov/ncas/alerts/AA19-122A

This Java program helps analyze Gateway logs (gw_log*) and automatically generates secinfo and reginfo files making SAP system administrator's life easy.

Refer SAP notes 821875, 1421005 and 1408081.

Message server ACLs are normally straightforward to maintain but it is quite overwhleming to write Gateway ACLs files- secinfo and reginfo. Follow below steps to turn on gateway security in simulation mode.

Turn on Gateway simulation using profile parameter gw/sim_mode =1

Update profile parameter gw/reg_no_conn_info value as per Note 1444282. Higher the better.

Change profile parameter gw/acl_mode=1

Use centralized ACL files by setting below profile parameters: gw/sec_info = $(DIR_GLOBAL)/secinfo gw/reg_info = $(DIR_GLOBAL)/reginfo

Turn on GW logging (refer note 2527689).Maintain this in profile as well. Change Parameter gw/logging=ACTION=SsPZ LOGFILE=gw_log-%y-%m-%d SWITCHTF=day

System will now start generating logs in work directory. Daily log file could be 100s of lines based on system configuration. After couple of weeks, copy all log files to say c:\gwlog directory.

Run this Java program and provide directory path and it will analyze all logs and generat secinfo and reginfo. Keep these files at $(DIR_GLOBAL) path to secure SAP servers.

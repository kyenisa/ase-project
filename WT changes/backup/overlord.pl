#!/usr/bin/perl
#
# $Id: overlord.pl 12577 2016-01-12 10:52:39Z jmanteiga $
#
# Copyright (c) 2005-2009, Copperfasten Technologies, Teoranta.  All rights
# reserved.  Unpublished rights reserved under the copyright laws of
# the United States and/or the Republic of Ireland.
#
# The software contained herein is proprietary to and embodies the
# confidential technology of Copperfasten Technologies, Teoranta.
# Possession, use, duplication or dissemination of the software and
# media is authorized only pursuant to a valid written license from
# Copperfasten Technologies, Teoranta.
#
#########################################################
# System config synchronizer.
#
# @author jinyedge
#########################################################
use strict;
use Encode;
use DBI;
use Data::Dumper;
use Daemon::Generic;
use MIME::Base64;
use POSIX qw/strftime/;
use POSIX 'setsid';
use lib "/blocker/bin";
use edgelib;

#use Unix::Syslog;
#use Unix::Syslog qw(:macros :subs);
#openlog("XLOG", LOG_PID, LOG_LOCAL7);
#########################################################
# Global.
$Daemon::Generic::force_quit_delay = 60;
$our_log_file = "/var/log/overlord/overlord.log";

my $dbh;
my $old_update_times = {};
my $new_update_times = {};
my $update_flags = {};

my $restart_flags = {};
my $reload_flags = {};
my $stop_flags = {};
my $skel_dir = "/blocker/conf/skeletons";
my $apache = "apache22";
`/usr/sbin/pkg info -q apache24`;
if ($? == 0) {
	$apache = "apache24";
	
}
my $www_conf_file = "/usr/local/etc/$apache/httpd.conf";

my $www_skel_file = "$skel_dir/httpd.skel";
my $smb_conf_file = "/usr/local/etc/smb.conf";

my $smb_skel_file = "$skel_dir/smb.skel";
my $hosts_conf_file = "/etc/hosts";
my $resolv_conf_file = "/etc/resolv.conf";
my $rc_conf_file = "/etc/rc.conf";

my $rc_skel_file = "$skel_dir/rc.skel";
my $squid_conf_file = "/blocker/proxy/etc/squid.conf";

my $squid_ssl_dir = "/usr/blocker/ssl";
my $squid_ssl_cache_db = "$squid_ssl_dir/ssl_db";

my $ssl_inspect_file = "/blocker/proxy/etc/sslinspect";
my $ssl_exclude_file = "/blocker/proxy/etc/sslexclude";
my $ssl_regex = "/blocker/proxy/etc/sslinspectregex";

my $squid_skel_file = "$skel_dir/squid.skel";
my $cachemgr_conf_file = "/blocker/proxy/etc/cachemgr.conf";

my $crontab_conf_file = "/etc/crontab";
my $crontab_skel_file = "$skel_dir/crontab.skel";

my $ntpd_conf_file = "/etc/ntp.conf";

my $squid_login_page = "/blocker/proxy/share/errors/templates/ERR_ESI";
my @windowsupdate_domains = (".microsoft.com", ".windowsupdate.com");

my $last_squid_reload = 0;
my $snmp_conf_file = "/usr/local/share/snmp/snmpd.conf";
my $snmp_conf_template = "/usr/local/share/snmp/snmpd.conf.template";

my $icapsvr_conf_file="/blocker/conf/icapsvr.conf";

#------------------------------------------------------
sub init_globals{
	if(!$dbh or !$dbh->selectrow_array("select 1")){
		$dbh = DBI->connect("DBI:Pg:dbname=titax","titax", "",
			{RaiseError => 0, PrintError => 1, AutoCommit => 1}) or do{

			append_err($DBI::errstr);
			return 0;
		};
	}

	# Fill the hash for update_times.
	unless(keys %$old_update_times){
		my $ra = $dbh->selectall_arrayref("select tname, mtime from update_times");
		for my $row(@$ra){
			$old_update_times->{$row->[0]} = $row->[1];
		}
	}
	my $ra = $dbh->selectall_arrayref("select tname, mtime from update_times");
	for my $row(@$ra){
		$new_update_times->{$row->[0]} = $row->[1];
	}
	return 1;
}

#------------------------------------------------------
sub get_update_time_args{
	my $tname = shift;

	my $line = $dbh->selectrow_array("select args from update_times where tname = '$tname'");
	
	$line or return ();
	return split /\s+/, $line;
}

#------------------------------------------------------
sub get_squid_cache_size{
	my $per = 0.5;		# Default cache disk size.

	# Get /cache line.
	my $line = `df -k | grep /cache`;

	# Get avail on /.
	unless($line){
		my @list = `df -k`;
		shift @list;
		$line = shift @list;
	}
		
	my @arr = split /\s+/, $line;

	# make it mega bytes.
	my $size = $arr[1];
	$size *= 0.001;
	$size = int($size);

	# reserve space for urldb.
	$size -= 2000;

	if($size < 1000){
		return 100;
	}

	if($size < 10000){
		$per = 0.4;		# Cache disk size when the HDD is smaller than 10G.
	}

	$size *= $per;

	# Max cache size is 20GB.
	my $max_squid_cache_size = 1024 * 20;
	if($size > $max_squid_cache_size){
		$size = $max_squid_cache_size;
	}

	return int $size;
}

#------------------------------------------------------
sub check_update_time{
	my $tname = shift;

	$new_update_times->{$tname} ne $old_update_times->{$tname} and do{
		$old_update_times->{$tname} = $new_update_times->{$tname};
		return 1;
	};
	return 0;
}

#------------------------------------------------------
sub check_windowsupdate_domains{
	for my$domain(@windowsupdate_domains){
		my $cnt = $dbh->selectrow_array("select count(*) from domain_policies
			where domain = '$domain' and type = 'SYSTEM'");

		$cnt or $dbh->do("insert into domain_policies(domain, auth_flag, filter_flag, block_flag, type)
			values('$domain', 'TRUE', 'TRUE', 'FALSE', 'SYSTEM')");
	}
}

#------------------------------------------------------
sub update_windowsupdate_conf{
	append_log("update_windowsupdate_conf, started");

	my $rh_authpolicy = $dbh->selectrow_hashref("select * from authpolicy");

	if($rh_authpolicy->{bypass_msupdate} eq "TRUE"){
		# Check if there're domains first.
		check_windowsupdate_domains();

		for my$domain(@windowsupdate_domains){
			$dbh->do("update domain_policies set auth_flag = 'TRUE', filter_flag = 'TRUE'
				where domain = '$domain' and type = 'SYSTEM'");
		}
	}
	else{
		for my$domain(@windowsupdate_domains){
			$dbh->do("update domain_policies set auth_flag = 'FALSE', filter_flag = 'FALSE'
				where domain = '$domain' and type = 'SYSTEM'");
		}
	}
	
	append_log("update_windowsupdate_conf, end");
}

#------------------------------------------------------
sub is_icap_needed{

	my $q = "select count(*) from policyflags where pagefilter = 'TRUE' or sizefilter = 'TRUE'";
	if($dbh->selectrow_array($q)){
		return 1;
	}

	my $q = "select count(*) from filtering where avscan = 'TRUE'";
	if($dbh->selectrow_array($q)){
		return 1;
	}

	return 0;
}

#------------------------------------------------------
sub is_df_enabled{

	my $q = "select count(*) from filtering where df_enable = 'TRUE'";
	if($dbh->selectrow_array($q)){
		return 1;
	}

	return 0;
}

sub update_safe_search{
    my $reload_flag = 0;
                
    append_log("update_safe_search, started");

 	my $q3="select searchengine from policyflags f  join policysafesearch s on f.policyid = s.policyid where safesearch='SAFESEARCH_ON' or (safesearch='SAFESEARCH_CUSTOM' and option<>'OFF') group by searchengine;";
	my $ra = $dbh->selectall_arrayref($q3);

    my @engines;
    my $e;
    for my $row(@$ra) {
		$e=$row->[0];
		#$e =~ s/msn/bing/g;
		push @engines, ".$e.*";
    }

    my $engines_text = join "\n", @engines;
    my $engines_file = "/tmp/ssl_regex";
    write_text_file($engines_file, $engines_text);
    if(-f $ssl_inspect_file){
        `$our_diff $ssl_regex $engines_file` and $reload_flag = 1;
    }
    else{
        $reload_flag = 1;
    }
    `$our_sudo_mv $engines_file $ssl_regex`;

    # Set reload flag.
    if($reload_flag){
        if(!$reload_flags->{squid}){
			append_log("Trying to reload proxy");
			$last_squid_reload = time;
			$reload_flags->{squid} = 1;
			`$our_sudo /blocker/proxy/sbin/proxy -k reconfigure`;
			$last_squid_reload = time;
			append_log("Proxy reloaded");
			$reload_flags->{squid} = 0;
        };
        #$reload_flags->{squid} = 1;
    }
    else{
        append_log("update_safe_search, nothing to update");
    }

    append_log("update_safe_search, done");
}



sub update_ssl_domains{
    my $reload_flag = 0;

    append_log("update_ssl_domains, started");

    # Read domains.
    my $q = "select domain, inspect_flag from ssl_domains order by id";
    my $ra = $dbh->selectall_arrayref($q);

    my @inspect;
    my @exclude;
    for my $row(@$ra) {
        if ($row->[1] == 1){
           push @inspect, $row->[0];
        }
        else{
           push @exclude, $row->[0];
        }
    }

    my $inspect_text = join "\n", @inspect;
    my $tmp_inspect = "/tmp/inspect";
    write_text_file($tmp_inspect, $inspect_text);
    if(-f $ssl_inspect_file){
        `$our_diff $ssl_inspect_file $tmp_inspect` and $reload_flag = 1;
    }
    else{
        $reload_flag = 1;
    }
    `$our_sudo_mv $tmp_inspect $ssl_inspect_file`;

    my $exclude_text = join "\n", @exclude;
    my $tmp_exclude = "/tmp/inspect";
    write_text_file($tmp_exclude, $exclude_text);
    if(-f $ssl_exclude_file){
        `$our_diff $ssl_exclude_file $tmp_exclude` and $reload_flag = 1;
    }
    else{
        $reload_flag = 1;
    }
    `$our_sudo_mv $tmp_exclude $ssl_exclude_file`;

    # Set reload flag.
    if($reload_flag){
        $reload_flags->{squid} = 1;
    }
    else{
        append_log("update_ssl_domains, nothing to update");
    }

    append_log("update_ssl_domains, done");
}

#------------------------------------------------------
sub update_squid_conf{
	my $do_not_restart = shift;

	append_log("update_squid_conf, started");

	unless(-f $squid_skel_file){
		append_err("$squid_skel_file missing");
		return;
	}

	my $rh_networking = $dbh->selectrow_hashref("select * from networking");
	my $rh_filtering = $dbh->selectrow_hashref("select * from filtering");
	my $rh_cache = $dbh->selectrow_hashref("select * from cache");
	my $rh_authpolicy = $dbh->selectrow_hashref("select * from authpolicy");

	# Top setting.
	my $hostname = $rh_networking->{hostname};
	my $domain = $rh_networking->{domain};
	my $int_ip = $rh_networking->{int_ip};
	my $transparentproxy = $rh_networking->{transparentproxy};
	my $router_ip = $rh_networking->{router_ip};
	my $cache_mgr = $rh_cache->{cache_mgr};
	my $cnames = $rh_networking->{cnames};
	my $squid_port = $rh_cache->{httpport};
        my $ssl_inspection = $rh_filtering->{ssl_inspection};
        my $ssl_mode = $rh_filtering->{ssl_mode};
        my $ssl_cert = $rh_filtering->{ssl_cert};
        my $cache_mem = $rh_filtering->{cache_mem};
        my $workers = $rh_filtering->{workers};
	my $squid_ssl_cert = "$squid_ssl_dir/ssl_cert/$ssl_cert";

        my $ssl_bump = qq(ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=$squid_ssl_cert);
	my $squid_https_port = 8882;
	my $http_port = qq(
http_port $int_ip:$squid_port sslinspection
http_port 127.0.0.1:$squid_port intercept
	);

        my $https_port = "";
        my $ssl_config = "";

        if ($ssl_inspection == 0) {
		$http_port =~ s/sslinspection//;
        }
        else {
		$http_port =~ s/sslinspection/$ssl_bump/;
		$ssl_config .= qq(
sslproxy_cert_error allow all
sslproxy_flags DONT_VERIFY_PEER
sslcrtd_program /blocker/proxy/libexec/ssl_crtd -s $squid_ssl_cache_db -M 4MB

acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3
);

		if ($ssl_mode eq 'inspect') {
			$ssl_config .= qq(
acl ssl_file dstdomain "$ssl_inspect_file"
acl ssl_regex dstdom_regex -i "$ssl_regex"
acl ssl_inspect any-of ssl_file ssl_regex
ssl_bump peek step1 all
ssl_bump bump step2 ssl_inspect
ssl_bump splice step2 all
);
		}
		elsif ($ssl_mode eq 'exclude') {
			$ssl_config .= qq(
acl ssl_file dstdomain "$ssl_exclude_file"
acl ssl_regex dstdom_regex -i "$ssl_regex"
acl ssl_exclude any-of ssl_file ssl_regex
ssl_bump peek step1 all
ssl_bump splice step2 ssl_exclude
ssl_bump bump step2 all
);
		}
		else {
			$ssl_config .= qq(
ssl_bump peek step1 all
ssl_bump bump step2 all
);
		}
        }

        $http_port = trim($http_port);
	if("TRUE" ne $transparentproxy){
		$http_port =~ s/intercept//;
	} elsif ($ssl_inspection == 1) {
		$https_port = qq(
https_port 127.0.0.1:$squid_https_port intercept $ssl_bump
);
        }

	my $skel = read_text_file($squid_skel_file);
	$skel =~ s/#{visible_hostname}/visible_hostname $hostname/;
	$skel =~ s/#{http_port}/$http_port/;
	$skel =~ s/#{https_port}/$https_port/;
	$skel =~ s/#{ssl_config}/$ssl_config/;
	$skel =~ s/#{append_domain}/append_domain \.$domain/;

	# Cache manager.
	if($cache_mgr){
		$skel =~ s/#{cache_mgr}/cache_mgr $cache_mgr/;
	}
	else{
		$skel =~ s/#{cache_mgr}/#/;
	}

	# cache_mem.
	if($cache_mem){
		$skel =~ s/#{cache_mem}/cache_mem $cache_mem/;
	} else{
		$skel =~ s/#{cache_mem} MB/#/;
	}

	# Cache setting.
	my $cacheon = $rh_cache->{cacheon} eq "TRUE" ? 1 : 0;
	my $cache_size = get_squid_cache_size();

	my $cache_conf = "cache_dir aufs /cache $cache_size 16 256\ncache deny all";
	if($cacheon){
		$cache_conf = "cache_dir aufs /cache $cache_size 16 256";
	}
	$skel =~ s/#{cache_conf}/$cache_conf/;

	my $q = qq(
select domain from urlglobalhandling
where type='CACHE'
order by length(domain)
	);
	my $ra = $dbh->selectall_arrayref($q);

	my $uncacheddomains;
	for my $row(@$ra){
		my $domain = $row->[0];
		$uncacheddomains .= "acl uncacheddomains dstdomain $domain\n";
	}
	if($uncacheddomains){
		$uncacheddomains .= "cache deny uncacheddomains";
	}

	$skel =~ s/#{uncacheddomains}/$uncacheddomains/;

	# Streaming setting.
	my $allow_audio = $rh_filtering->{allowaudio} eq "TRUE" ? 1 : 0;
	my $allow_video = $rh_filtering->{allowvideo} eq "TRUE" ? 1 : 0;

	my $allow_audio_line = "http_reply_access deny audio";
	if($allow_audio){
		$allow_audio_line = "http_reply_access allow audio";
	}
	$skel =~ s/#{allow_audio}/$allow_audio_line/;

	my $allow_video_line = "http_reply_access deny video";
	if($allow_video){
		$allow_video_line = "http_reply_access allow video";
	}
	$skel =~ s/#{allow_video}/$allow_video_line/;

	# http_access allow windowsupdate
	my $allow_windowsupdate = "http_access allow windowsupdate";
	$rh_authpolicy->{bypass_msupdate} eq "FALSE" and $allow_windowsupdate = "";

	$skel =~ s/#{allow_windowsupdate}/$allow_windowsupdate/;

	# Authenticators.
	my $enable_auth = $rh_authpolicy->{enable_auth} eq "TRUE" ? 1 : 0;
	my $allow_ldap = $rh_authpolicy->{allow_ldap} eq "TRUE" ? 1 : 0;
	my $allow_kshield = $rh_authpolicy->{allow_kshield} eq "TRUE" ? 1 : 0;
	my $enable_ntlm = $rh_authpolicy->{enable_ntlm} eq "TRUE" ? 1 : 0;
	my $basic_auths = $rh_authpolicy->{basic_auths};
	my $ntlm_auths = $rh_authpolicy->{ntlm_auths};
	my $kshield_server = $rh_authpolicy->{kshield_server};
	my $kshield_userkey = $rh_authpolicy->{ldap_username_field} eq "" ? "sAMAccountName" : $rh_authpolicy->{ldap_username_field};
	my $kshield_apikey = $rh_authpolicy->{kshield_apikey};
	my $ip_session = $rh_authpolicy->{ip_session}  eq "TRUE" ? 1 : 0;
	my $ip_session_ttl = $rh_authpolicy->{ip_session_ttl};

	my $auth_text = "";
	my $kshield_ttl_text = "";
        if ($ip_session) {
           $kshield_ttl_text = "$ip_session_ttl seconds";
        } else {
           $kshield_ttl_text = "1 hour";
        }

	if($allow_kshield){
		$auth_text = qq(
auth_param kshield program /blocker/bin/squid_keyshield_auth.pl "$kshield_server" "$kshield_userkey" "$kshield_apikey"
auth_param kshield children $basic_auths
auth_param kshield credentialsttl $kshield_ttl_text

                );
	}

	if($allow_ldap){
		$auth_text = qq(
auth_param basic program /blocker/bin/proxy_auth.pl
auth_param basic children $basic_auths
auth_param basic realm Internet via WebTitan
auth_param basic credentialsttl 1 hour
		);
	}

	if($enable_ntlm){
		$auth_text = qq(
auth_param ntlm program /usr/local/bin/ntlm_auth --helper-protocol=squid-2.5-ntlmssp
auth_param ntlm children $ntlm_auths
auth_param ntlm keep_alive off
		);
	}
	else{
		$stop_flags->{smb} = 1;
	}

	# If auth is not enabled in db or transparet proxy enabled
	# there should be no authenticator in squid.conf.
	$enable_auth or $auth_text = "";
#	"TRUE" eq $transparentproxy and $auth_text = "";

	$auth_text or $auth_text = qq(
auth_param basic program /blocker/bin/proxy_auth.pl
);
	$auth_text = trim($auth_text);
	$skel =~ s/#{auth_text}/$auth_text/;

	# ICAP.
	my $enable_icap = 0;
	my $icap_onoff = "off";
	if(is_icap_needed()){
		$enable_icap = 1;
		$icap_onoff = "on";
	}
	$skel =~ s/#{icap_onoff}/$icap_onoff/;
	
	# Misc setting.
	my $misc_text;
	my $enablefwdhdr = $rh_cache->{enablefwdhdr} eq "TRUE" ? 1 : 0;
	my $enableviahdr = $rh_cache->{enableviahdr} eq "TRUE" ? 1 : 0;
	unless($enablefwdhdr){
		$misc_text .= "request_header_access X-Forwarded-For deny all\n";
	}
	unless($enableviahdr){
		$misc_text .= "request_header_access Via deny all\n";
	}
	$skel =~ s/#{misc_text}/$misc_text/;

	#
	# Upstream Proxy settings
	# SSL-Bumped traffic cannot be sent to peer
	#
	my $fwproxy = $rh_cache->{fwproxy} eq "TRUE" ? 1 : 0;
	my $fwtraffic = $rh_cache->{fwtraffic};
	my $fwprotocols = $rh_cache->{fwprotocols};
	my $fwproxyhost = $rh_cache->{fwproxyhost};
	my $fwproxyport = $rh_cache->{fwproxyport};

	my $fwdomain;
	$q = "select domain from urlglobalhandling where type='FWD' order by length(domain)";
	$ra = $dbh->selectall_arrayref($q);
	for my $row(@$ra){
		my $domain = $row->[0];
		$fwdomain .= "acl forwardTraffic dstdomain $domain\n";
	}
	$fwdomain = trim($fwdomain);

	my $fw_text;
	if($fwtraffic ne "FORWARD_ALL_TRAFFIC" and $fwdomain) {
		$fw_text = "$fwdomain\n";
	}
	$fw_text .= "# Upstream proxy\n";
	$fw_text .= "cache_peer $fwproxyhost parent $fwproxyport 0 no-query default\n";

        if ($ssl_inspection == 1) {
		# Cannot forward bump ssl traffic to peer
		$fw_text .= "# Bumped traffic cannot go via cache peer\n";
		if ($ssl_mode eq 'inspect') {
			$fw_text .= "always_direct allow connect-traffic ssl_inspect\n";
			$fw_text .= "always_direct allow ssl-traffic ssl_inspect\n";
		} elsif ($ssl_mode eq 'exclude') {
			$fw_text .= "always_direct allow connect-traffic !ssl_exclude\n";
			$fw_text .= "always_direct allow ssl-traffic !ssl_exclude\n";
		} else {
			$fw_text .= "always_direct allow connect-traffic\n";
			$fw_text .= "always_direct allow ssl-traffic\n";
		}
	}

	if($fwprotocols eq "PROTO_HTTP_ONLY"){
		$fw_text .= "always_direct allow connect-traffic\n"; 
		$fw_text .= "always_direct allow ssl-traffic\n"; 
	} elsif($fwprotocols eq "PROTO_SSL_ONLY"){
		$fw_text .= "always_direct allow http-traffic\n"; 
	}

	if($fwtraffic eq "FORWARD_ALL_TRAFFIC"){
		$fw_text .= "never_direct allow all\n";
	} elsif($fwtraffic eq "FORWARD_SELECTED_TRAFFIC" and $fwdomain){
		$fw_text .= "always_direct deny forwardTraffic\n";
		$fw_text .= "always_direct allow all\n";
                $fw_text .= "never_direct allow all\n";
	} elsif($fwtraffic eq "FORWARD_UNSELECTED_TRAFFIC" and $fwdomain){
		$fw_text .= "always_direct allow forwardTraffic\n";
                $fw_text .= "never_direct allow all\n";
	}
	$fw_text = trim($fw_text);

	# Setup upstream proxy only when there's upstream proxy enabled.
	$fwproxy or $fw_text = "always_direct allow all\n";

	$skel =~ s/#{fw_text}/$fw_text/;

	# Get wccp_text.
	my $wccp_text;
	if("TRUE" eq $transparentproxy and $router_ip){
		$wccp_text = qq(
wccp2_router $router_ip
wccp2_forwarding_method 1
wccp2_return_method 1
wccp2_service standard 0
wccp2_service dynamic 70
wccp2_assignment_method hash
wccp2_service_info 70 protocol=tcp flags=dst_ip_hash priority=240 ports=443 
			);
	}
	$wccp_text = trim($wccp_text);

	$skel =~ s/#{wccp_text}/$wccp_text/;

	# SMP workers.
	if($workers){
		$skel =~ s/#{workers}/workers $workers/;
	} else{
		$skel =~ s/#{workers}/#/;
	}

	# Write conf file.
	my $tmp_file = "/tmp/squid.conf.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $squid_conf_file){
		my $diff_text = `$our_diff $squid_conf_file $tmp_file`;
		$diff_text = trim($diff_text);
		
		$diff_text or do{
			append_log("update_squid_conf, nothing to update");
			return;
		};

		$diff_text =~ /auth_param/ and do{
			unless($do_not_restart){
				$restart_flags->{squid} = 1;
				append_log("update_squid_conf, we need to restart proxy");
			}
		};

		if($diff_text and $enable_auth and $enable_ntlm){
			unless($do_not_restart){
				$restart_flags->{squid} = 1;
			}
		}

		if($diff_text and $enable_icap){
			unless($do_not_restart){
				$restart_flags->{squid} = 1;
			}
		}

	}

	`$our_sudo_mv $tmp_file $squid_conf_file`;

	# Set reload flag.
	unless($do_not_restart){
		$restart_flags->{squid} or $reload_flags->{squid} = 1;
	}

	append_log("update_squid_conf, done");
}

#------------------------------------------------------
sub update_hosts_conf{
	append_log("update_hosts_conf, started");
	my $q = "select hostname, domain, int_ip from networking";
	my($hostname, $domain, $int_ip) = $dbh->selectrow_array($q);

	$q = qq(
	select ntdcname, ntdcip, ntbkupdcname, ntbkupdcip from authpolicy
	where enable_auth = 'TRUE' and enable_ntlm = 'TRUE'
	);
	my($ntdcname, $ntdcip, $ntbkupdcname, $ntbkupdcip) = $dbh->selectrow_array($q);

	my $dcline = "";
	if($ntdcname and $ntdcip){
		$dcline .= "$ntdcip	$ntdcname";
	}
	if($ntbkupdcname and $ntbkupdcip){
		$dcline .= "\n$ntbkupdcip	$ntbkupdcname";
	}
	$dcline = trim($dcline);

	my $skel = qq(
127.0.0.1	localhost
$int_ip	$hostname
$int_ip	$hostname.$domain
$dcline
	);
	$skel =~ s/^\s+|\s+$//g;

	my $tmp_file = "/tmp/hosts.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $hosts_conf_file){
		`$our_diff $hosts_conf_file $tmp_file` or do{
			append_log("update_hosts_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $hosts_conf_file`;

	append_log("update_hosts_conf, done");
}

#------------------------------------------------------
sub update_cachemgr_conf{
	append_log("update_cachemgr_conf, started");
	my $hostname = $dbh->selectrow_array("select hostname from networking");
	my $squid_port = $dbh->selectrow_array("select httpport from cache");

	my $skel = "$hostname:$squid_port";

	my $tmp_file = "/tmp/cachemgr.conf.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $cachemgr_conf_file){
		`$our_diff $cachemgr_conf_file $tmp_file` or do{
			append_log("update_cachemgr_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $cachemgr_conf_file`;

	# Set reload flag.
	$reload_flags->{squid} = 1;

	append_log("update_cachemgr_conf, done");
}

#------------------------------------------------------
sub update_login_page{
	my $id = shift;

	append_log("update_login_page, started");

	$id or do{
		append_err("No id given");
		return;
	};

	my $intercept_login = $dbh->selectrow_array("select intercept_login from authpolicy");
	$intercept_login ne 'TRUE' and do{
		append_err("intercept_login was not enabled");
		return;
	};

	my $page = $dbh->selectrow_array("select page from loginpages where id = $id");
	if(!$page){
		append_err("No login page");
		return;
	}

	my $rh_networking = $dbh->selectrow_hashref("select * from networking");
	my $int_ip = $rh_networking->{int_ip};
	my $webuihttp = $rh_networking->{webuihttp} eq "TRUE" ? 1 : 0;
	my $uiprotocol = "http";
	my $uiport = "";
	if ($webuihttp) {
		$uiprotocol = "http";
		$uiport = $rh_networking->{webuiport};
		$uiport = $uiport eq "80" ? "" : ":$uiport";
	} else {
		$uiprotocol = "https";
		$uiport = $rh_networking->{webuihttpsport};
		$uiport = $uiport eq "443" ? "" : ":$uiport";
	}
	my $webtitan_url = "$uiprotocol://$int_ip$uiport/interceptlogin.php";
	my $decoded = decode_base64($page);

	# Add webtitan url.
	$decoded =~ s/%webtitan/$webtitan_url/g;

	write_text_file($squid_login_page, $decoded);

	# Set reload flag.
	$reload_flags->{squid} = 1;

	append_log("update_login_page, done");
}

#------------------------------------------------------
sub update_resolv_conf{
	append_log("update_resolv_conf, started");
	
	my $q = "select domain from networking";
	my($domain) = $dbh->selectrow_array($q);

	$q = "select int_dns1, int_dns2, int_dns3 from networking";
	my($int_dns1, $int_dns2, $int_dns3) = $dbh->selectrow_array($q);

	my $nameserverline = "";
	$nameserverline .= "domain $domain\n";
	$nameserverline .= "search $domain\n";
	if($int_dns1){
		$nameserverline .= "nameserver $int_dns1\n";
	}
	if($int_dns2){
		$nameserverline .= "nameserver $int_dns2\n";
	}
	if($int_dns3){
		$nameserverline .= "nameserver $int_dns3\n";
	}
	$nameserverline =~ trim($nameserverline);

	my $skel = $nameserverline;
	$skel =~ trim($skel);

	my $tmp_file = "/tmp/resolv.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $resolv_conf_file){
		`$our_diff $resolv_conf_file $tmp_file` or do{
			append_log("update_resolv_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $resolv_conf_file`;
	$restart_flags->{squid} = 1;
	
	append_log("update_resolv_conf, done");
}

#------------------------------------------------------
sub update_smb_conf{
	append_log("update_smb_conf, started");

	unless(-f $smb_skel_file){
		append_err("update_smb_conf, $smb_skel_file missing");
		return;
	}

	my $q = qq(
		select ntdomname, ntdcname, ntbkupdcname
		from authpolicy
		where enable_auth = 'TRUE' and enable_ntlm = 'TRUE'
		);
	my($ntdomname, $ntdcname, $ntbkupdcname) = $dbh->selectrow_array($q);
	$ntdomname = uc($ntdomname);

	unless($ntdomname){
		append_log("update_smb_conf, ntlm was not enabled");
		return;
	}

	my $skel = read_text_file($smb_skel_file);
	$skel =~ s/#{workgroup}/   workgroup = $ntdomname/;
	$skel =~ s/#{passserver}/   password server = $ntdcname $ntbkupdcname/;

	my $tmp_file = "/tmp/smb.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $smb_conf_file){
		`$our_diff $smb_conf_file $tmp_file` or do{
			append_log("update_smb_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $smb_conf_file`;

	append_log("update_smb_conf, done");
}

#------------------------------------------------------
sub get_static_routes{
	my $q = "select id, ipnetwork, gateway, type from staticroutes where active = 'TRUE'";
	my $ra = $dbh->selectall_arrayref($q);

	@$ra or return "";

	my @arr;
	my @lines;
	for my $row(@$ra){
		my $id = $row->[0];
		my $ipnetwork = $row->[1];
		my $gateway = $row->[2];
		my $type = $row->[3];

		push @arr, $id;

		$type = lc $type;

		my $line = "route_$id=\"-$type $ipnetwork $gateway\"";
		$line =~ s/\s+"$/"/;
		push @lines, $line;
	}

	my $res_line = sprintf "static_routes=\"%s\"\n", join " ", @arr;
	$res_line .= join "\n", @lines;
}

#------------------------------------------------------
sub update_rc_conf{
	append_log("update_rc_conf, started");

	unless (-f "$rc_skel_file") {
		append_err("$rc_skel_file missing");
		return;
	}

	my $q = qq(
		select hostname, domain, gateway, int_ip, int_subnet, transparentproxy
		from networking
		);
	my($hostname, $domain, $gateway, $int_ip, $int_subnet, $transparentproxy) = $dbh->selectrow_array($q);

	my $rh_authpolicy = $dbh->selectrow_hashref("select * from authpolicy");
	my $enable_auth = $rh_authpolicy->{enable_auth} eq "TRUE" ? 1 : 0;
	my $enable_ntlm = $rh_authpolicy->{enable_ntlm} eq "TRUE" ? 1 : 0;

	my $samba_enable = "NO";
	my $winbindd_enable = "NO";
	if($enable_auth and $enable_ntlm){
		$samba_enable = "YES";
		$winbindd_enable = "YES";
	}

	my $fqdn = $hostname;
	$domain and $fqdn = "$hostname.$domain";

	my $ifname = get_ifname();
	my $ifname_line = "ifconfig_$ifname";

	my $static_routes = get_static_routes();

	# ipfw and natd.
	my $ipfwd_enable = "NO";
	my $natd_enable = "NO";
	my $gateway_enable = "NO";
	my $natd_interface_line = "natd_interface=\"$ifname\"";
	if("TRUE" eq $transparentproxy){
		$ipfwd_enable = "YES";
		$natd_enable = "YES";
		$gateway_enable = "YES";
	}


	my $skel = read_text_file($rc_skel_file);

        if (is_snmpd_enabled()){
                $skel =~ s/#{snmpd_enable}/YES/;
                $restart_flags->{snmpd} = 1;
                $stop_flags->{snmpd} = 0;
        } else {
                $skel =~ s/#{snmpd_enable}/NO/;
                $restart_flags->{snmpd} = 0;
                $stop_flags->{snmpd} = 1;
        }

	$skel =~ s/#{defaultrouter}/$gateway/;
	$skel =~ s/#{hostname}/$fqdn/;
	$skel =~ s/#{ifname_line}/$ifname_line/;
	$skel =~ s/#{int_ip}/$int_ip/;
	$skel =~ s/#{int_subnet}/$int_subnet/;
	$skel =~ s/#{samba_enable}/$samba_enable/;
	$skel =~ s/#{winbindd_enable}/$winbindd_enable/;
	$skel =~ s/#{ipfwd_enable}/$ipfwd_enable/;
	$skel =~ s/#{natd_enable}/$natd_enable/;
	$skel =~ s/#{gateway_enable}/$gateway_enable/;
	$skel =~ s/#{natd_interface_line}/$natd_interface_line/;
	$skel =~ s/#{static_routes}/$static_routes/;

	 
	# ntpd.
	my $rh_datetime = $dbh->selectrow_hashref("select * from datetime");
	my $ntpenabled = $rh_datetime->{ntpenabled} eq "TRUE" ? 1 : 0;
	if($ntpenabled){
		$skel =~ s/#{ntpd_enable}/YES/;

	}
	else{
		$skel =~ s/#{ntpd_enable}/NO/;
	}

	# clamd.
	my $rh_filtering = $dbh->selectrow_hashref("select * from filtering");
	my $avscan = $rh_filtering->{avscan} eq "TRUE" ? 1 : 0;
	if($avscan){
		$skel =~ s/#{clamd_enable}/YES/;
	}
	else{
		$skel =~ s/#{clamd_enable}/NO/;
	}

	# If there's no difference.
	my $tmp_file = "/tmp/rc.conf.tmp";
	write_text_file($tmp_file, $skel);
	
	if (-f "$rc_conf_file"){
		`$our_diff $rc_conf_file $tmp_file` or do{
			append_log("update_rc_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $rc_conf_file`;

	my $old_hostname = trim(`/bin/hostname`);
	if($old_hostname ne $fqdn){
		`$our_sudo /bin/hostname $fqdn`;
	}

	# Set restart flag.
	$restart_flags->{network} = 1;
	$restart_flags->{squid} = 1;
	$restart_flags->{ntpd} = 1;
	$restart_flags->{clamd} = 1;
	$restart_flags->{intercept} = 1;
	
	append_log("update_rc_conf, done");
}
#------------------------------------------------------
#if snmpd.conf file is missing at the boot of machine and snmpd should be running from the begining (db entry)
#this method will recreate snmpd.conf file and update rc.conf to to allow for snmpd to start at boot/restart (overload).

sub recreate_snmp_conf{

	my $skel;
	my $tmp_file = "/tmp/rc.conf.tmp";
	unless (-f "$snmp_conf_file") {
		if (is_snmpd_enabled())
		{
			update_snmp_conf();

			open FH, "/etc/rc.conf";
			my @lines = <FH>;
			close FH;
			for my $line(@lines){
				$line =~ /^#/ and next;

				$line =~ /snmpd_enable/ and do{
				$line =~ s/^.*=//g;
				$line =~ s/["\s]//g;
					if ($line eq "NO") {
						$skel = read_text_file($rc_conf_file);
						$skel =~ s/snmpd_enable=\"NO\"/snmpd_enable=\"YES\"/;
						write_text_file($tmp_file, $skel);
						`$our_sudo_mv $tmp_file $rc_conf_file`;
						return 1;
					}
				next;
				};
			}
		}
	}
	return 0;
}
#------------------------------------------------------
sub update_snmp_conf
{
	append_log("update_snmp_conf, started");

	#other possible test query 	
	#select count(*), sys_location, sys_name, sys_contact, community, access from snmp where enabled=true group by sys_location, sys_name, sys_contact, community, access limit 1
	my $q = "select sys_location, sys_name, sys_contact, community, access from snmp where enabled=true";
	my($sys_location, $sys_name, $sys_contact, $community, $access) = $dbh->selectrow_array($q);
	

	#UI cannot pass empty values/string to db - because this test will break;
	if ((!$community) and (!$sys_name)) {
		#stop if there is something to stop
		$stop_flags->{snmpd} = 1;
		append_log("update_snmp_conf, nothing to update, done");
		return;
	};


	my $T_sys_location="%%SYS_LOCATION%%";
	my $T_sys_name="%%SYS_NAME%%";
	my $T_sys_contact="%%SYS_CONTACT%%";
	my $T_community="%%SYS_COMMUNITY%%";
	my $T_access="%%SYS_ADDRESS%%";

	sub line_replace
	{
		$_[0] =~ s/$_[1]/$_[2]/;
	
	}

	my @res_lines;
	if(-f $snmp_conf_template){		
		my $lines = read_text_file_arrayref($snmp_conf_template);
		for my $line(@$lines){
			$line = trim($line);
			
			$line =~ /$T_sys_location/ and do{
				line_replace($line,$T_sys_location,$sys_location);
			};
			$line =~ /$T_sys_name/ and do{
				line_replace($line,$T_sys_name,$sys_name);
			};
			$line =~ /$T_sys_contact/ and do{
				line_replace($line,$T_sys_contact,$sys_contact);
			};
			$line =~ /$T_community/ and do{
				if ($access!="") {
					my @access_ar=split(/,/, $access);
					for my $ip(@access_ar){
						line_replace($ip,$ip,"rocommunity $community $ip");							
					}
					# 127.0.0.1 must always be allowed - even if not specified
					@access_ar = grep(!/127.0.0.1/, @access_ar);
					push @access_ar, "rocommunity $community 127.0.0.1";
					$access= join "\n", @access_ar;
				} else {
					$access="rocommunity $community";
				}
				line_replace($line,$T_community,$access);
			};
			push @res_lines, $line;
		}
	}

	my $tmp_file ="/tmp/snmpd.tmp";
	my $skel = join "\n", @res_lines;
	open(FILE,">", $tmp_file);
	print FILE $skel;
	close(FILE);

	unless (-e "$tmp_file") {
		$stop_flags->{snmpd} = 1;
		$restart_flags->{snmpd} = 0;
		append_log("update_snmp_conf, error cannot create file $tmp_file");
		return;
	};
	`$our_sudo_mv $tmp_file $snmp_conf_file`;
	unless (-e "$snmp_conf_file") {
		$stop_flags->{snmpd} = 1;
		$restart_flags->{snmpd} = 0;
		append_log("update_snmp_conf, error cannot create file $snmp_conf_file");
		return;
	};
	$stop_flags->{snmpd} = 0;
	$restart_flags->{snmpd} = 1;

	append_log("update_snmp_conf, done");
	
};
#------------------------------------------------------
sub is_snmpd_enabled{
	if($dbh->selectrow_array("select count(*) from snmp where enabled = true")){
		return 1;
	}
	return 0;
}
#------

#------------------------------------------------------
sub update_ntpd_conf{
	append_log("update_ntpd_conf, started");

	my $q = "select ntp1, ntp2, ntp3 from datetime";
	my($ntp1, $ntp2, $ntp3) = $dbh->selectrow_array($q);
	
	# /etc/ntp.conf
	my $skel = "";
	$ntp1 and $skel .= "server $ntp1\n";
	$ntp2 and $skel .= "server $ntp2\n";
	$ntp3 and $skel .= "server $ntp3\n";
	$skel .= "driftfile /var/db/ntp.drift";

	my $tmp_file = "/tmp/ntp.conf.tmp";
	write_text_file($tmp_file, $skel);

	if(-f $ntpd_conf_file){
		`$our_diff $ntpd_conf_file $tmp_file` or do{
			append_log("update_ntpd_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $ntpd_conf_file`;

	# Set restart flag.
	$restart_flags->{ntpd} = 1;

	append_log("update_ntpd_conf, done");
}

#------------------------------------------------------
sub update_crontab_conf{
	append_log("update_crontab_conf, started");

	unless(-f $crontab_skel_file){
		append_err("$crontab_skel_file missing");
		return;
	}

	# Ldap-sync.
	my $ldapsync;
	my $q = "select id, importperiod from ldapservers where importperiodic = 'TRUE'";
	my $ra = $dbh->selectall_arrayref($q);
	for my $row(@$ra){
		my $id = $row->[0];
		my $period = $row->[1];

		$period % 60 != 0 and next;
		
		$period = $period / 60;

		if($period < 60){
			$ldapsync .= "*/$period * * * * root /blocker/bin/ldap_sync.pl $id > /dev/null 2>&1\n";
		}
		elsif($period == 60){
			$ldapsync .= "0 * * * * root /blocker/bin/ldap_sync.pl $id > /dev/null 2>&1\n";
		}
		elsif($period < 1440){
			$ldapsync .= sprintf("0 */%d * * * root /blocker/bin/ldap_sync.pl $id > /dev/null 2>&1\n", $period / 60);
		}
		elsif($period == 1440){
			$ldapsync .= "0 0 * * * root /blocker/bin/ldap_sync.pl $id > /dev/null 2>&1\n";
		}
		elsif($period < 44640){
			$ldapsync .= sprintf("0 0 */%d * * root /blocker/bin/ldap_sync.pl $id > /dev/null 2>&1\n", $period / 1440);
		}
	}
	$ldapsync = trim($ldapsync);
	$ldapsync or $ldapsync = "#";

	# Report.
	my $report;
	$q = "select time from reportscheduling where enabled = 'TRUE'";
	my $time = $dbh->selectrow_array($q);
	if($time){
		my($hour, $min) = split /:/, $time;
		$report = "$min $hour * * * root /usr/local/bin/wt-scheduledreports.php > /dev/null 2>&1";
	}
	$report = trim($report);
	$report or $report = "#";

	# Backup.
	my $backup;
	$q = "select freq, ftphost, ftpuser, ftppass, ftppath from backup where enable = 'TRUE'";
	my($freq, $ftphost, $ftpuser, $ftppass, $ftppath) = $dbh->selectrow_array($q);
	if($freq){
		$backup = "$freq root /usr/local/bin/wt-backup.pl > /dev/null 2>&1";
	}
	$backup = trim($backup);
	$backup or $backup = "#";

	# Alert.
	my $alert;
	$q = "select testinterval, reason from alerts where enabled = 'TRUE'";
	$ra = $dbh->selectall_arrayref($q);
	for my $row(@$ra){
		my $testinterval = $row->[0];
		my $reason = $row->[1];

		$testinterval or next;

		$alert .= "$testinterval root /blocker/bin/alerter.pl $reason > /dev/null 2>&1\n";
	}
	$alert = trim($alert);
	$alert or $alert = "#";

	# SNMP
	my $snmp;
	if (is_snmpd_enabled()){
		$snmp = "*/5 * * * * root /usr/local/bin/wt_updateSnmpDB.sh > /dev/null 2>&1\n";	
	}
	$snmp or $snmp = "#";



	# Write new crontab.
	my $skel = read_text_file($crontab_skel_file);
	
	$skel =~ s/#{ldapsync}/$ldapsync/;
	$skel =~ s/#{report}/$report/;
	$skel =~ s/#{backup}/$backup/;
	$skel =~ s/#{alert}/$alert/;
	$skel =~ s/#{snmp}/$snmp/;

	my $tmp_file = "/tmp/crontab.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $crontab_conf_file){
		`$our_diff $crontab_conf_file $tmp_file` or do{
			append_log("update_crontab_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $crontab_conf_file`;

	append_log("update_crontab_conf, done");
}

#------------------------------------------------------
sub update_urlsvr_conf{
	my $cloud_only = shift;

	append_log("update_urlsvr_conf, started");

	my $q = "select fwproxy, fwproxyhost, fwproxyport from cache";
	my($fwproxy, $fwproxyhost, $fwproxyport) = $dbh->selectrow_array($q);
	
	my $urlsvr_conf_file = "/blocker/conf/urlsvr.cfg";
	my @res_lines;
	if(-f $urlsvr_conf_file){
		my $lines = read_text_file_arrayref($urlsvr_conf_file);
		for my $line(@$lines){
			$line = trim($line);
			
			$line =~ /^proxy_url/ and do{
				if($fwproxy eq "TRUE" and $fwproxyhost and $fwproxyport){
					$line = "proxy_url = $fwproxyhost:$fwproxyport";
				}
				else{
					$line = "proxy_url =";
				}
			};
			$line =~ /^proxy_use/ and do{
				if($fwproxy eq "TRUE" and $fwproxyhost and $fwproxyport){
					$line = "proxy_use = 1";
				}
				else{
					$line = "proxy_use = 0";
				}
			};

			$cloud_only and $line =~ /^cloud_only/ and do{
				if($cloud_only eq "TRUE"){
					$line = "cloud_only = 1";
				}
				else{
					$line = "cloud_only = 0";
				}
			};

			push @res_lines, $line;
		}
	}

	my $skel = join "\n", @res_lines;

	my $tmp_file = "/tmp/urlsvr.tmp";
	write_text_file($tmp_file, $skel);
	if(-f $urlsvr_conf_file){
		`$our_diff $urlsvr_conf_file $tmp_file` or do{
			append_log("update_urlsvr_conf, nothing to update");
			return;
		};
	}

	`$our_sudo_mv $tmp_file $urlsvr_conf_file`;

	pkill("urlsvr");

	append_log("update_urlsvr_conf, done");
}

#------------------------------------------------------
sub reverse_conf{
	append_log("reverse_conf, started");

	open FH, "/etc/rc.conf";
	my @lines = <FH>;
	close FH;

	my $gateway;
	my $hostname;
	my $domain;
	my $int_ip;
	my $int_subnet;
	for my $line(@lines){
		$line =~ /^#/ and next;

		$line =~ /defaultrouter/ and do{
			$line =~ s/^.*=//g;
			$line =~ s/["\s]//g;
			$gateway = $line;
			next;
		};

		$line =~ /hostname/ and do{
			$line =~ s/^.*=//g;
			$line =~ s/["\s]//g;

			my @arr = split /\./, $line;

			$hostname = shift @arr;
			$domain = join ".", @arr;

			$domain or $domain = "example.com";

			next;
		};

		$line =~ /ifconfig/ and do{
			$line =~ s/^.*=//g;
			$line =~ s/["a-zA-Z]//g;
			$line = trim($line);

			my @arr = split /\s+/, $line;
			
			$int_ip = shift @arr;
			$int_subnet = shift @arr;
			
			next;
		};
	}

	@lines = `grep nameserver /etc/resolv.conf`;
	my $i = 1;
	my($int_dns1, $int_dns2, $int_dns3);
	for my $line(@lines){
		$line = trim($line);
		$line or next;
		$line =~ /nameserver/ or next;

		#$line =~ s/nameserver //;
		$line =~ s/[a-zA-Z\s]//g;

		if($i == 1){
			$int_dns1 = $line;
		}
		if($i == 2){
			$int_dns2 = $line;
		}
		if($i == 3){
			$int_dns3 = $line;
		}

		$i++;
	}

	# Check values.
	$gateway or do{
		append_err("There's no gateway value from rc.conf");
		return;
	};
	$hostname or do{
		append_err("There's no hostname value from rc.conf");
		return;
	};
	$domain or do{
		append_err("There's no domain value from rc.conf");
		return;
	};
	$int_ip or do{
		append_err("There's no int_ip value from rc.conf");
		return;
	};
	$int_subnet or do{
		append_err("There's no int_subnet value from rc.conf");
		return;
	};

	my $q = qq(
	select count(*) from networking
	where gateway = '$gateway'
	and hostname = '$hostname'
	and domain = '$domain'
	and int_ip = '$int_ip'
	and int_subnet = '$int_subnet'
	and int_dns1 = '$int_dns1'
	and int_dns2 = '$int_dns2'
	and int_dns3 = '$int_dns3'
	);

	if($dbh->selectrow_array($q) >= 1){
		append_log("reverse_conf, nothing to change");
		return;
	}
	
	$q = qq(
	update networking
	set hostname = '$hostname'
	, gateway = '$gateway'
	, domain = '$domain'
	, int_ip = '$int_ip'
	, int_subnet = '$int_subnet'
	, int_dns1 = '$int_dns1'
	, int_dns2 = '$int_dns2'
	, int_dns3 = '$int_dns3'
	);
	$dbh->do($q);

	append_log("reverse_conf, $q");
	append_log("reverse_conf, done");
}

#------------------------------------------------------
sub chk_urlcategories{
	append_log("chk_urlcategories, started");

	my $q = "select count(*) from urlcategories where categoryid <= 53";
	my $cnt = $dbh->selectrow_array($q);
	if($cnt == 53){
		append_log("chk_urlcategories, no need to proceed");
		return;
	}

	append_err("chk_urlcategories, There're only $cnt system categories");

	# Read and insert categoires.
	my $file_lines = read_text_file_arrayref("/blocker/conf/categories.txt");

	$dbh->do("delete from urlcategories where type = 'SYSTEM'");

	my $i = 0;
	for my $line(@$file_lines){
		my @a = split /\t/, $line;
		@a = map {s/\'/\'\'/g; $_;} @a;

		my $id = $a[0];
		my $name = $a[1];
		my $desc = $a[2];

		# max system category id = 54.
		# we only need to use 53 categories from sitefilter.
		# sitefilter category id starts from 1.
		# db category id starts from 0.
		$id > 54 and next;

		# Sitefilter numbering to db numbering system.
		$id = $id - 1;

		$name = encode('utf8', $name);
		$desc = encode('utf8', $desc);

		$q = "insert into urlcategories(categoryid, type, name, description) values($id, 'SYSTEM', '$name', '$desc')";
		$dbh->do($q);
	} 

	append_log("chk_urlcategories, done");
}

#------------------------------------------------------
sub init_conf{
	# Make dirs.
	my @dirs = qw(/blocker/sitefilter /blocker/reports /blocker/faultreports /cache);
	for my $dir(@dirs){
		-d $dir or `$our_sudo_mkdir $dir`;
		-d $dir or do{
			append_err_die("Can't make a directory, $dir");
		};
	}

	# Set owner.
	`$our_sudo_chown -R webtitan:webtitan /blocker`;
	`$our_sudo_chown -R nobody:nobody /cache`;
	# Set permission.
	`$our_sudo_chmod 777 /blocker/faultreports`;

	
	# Update config files.
	recreate_snmp_conf();
        #update_snmp_conf();
	update_crontab_conf();
	update_squid_conf(1);

	# Build cache for Squid.
	-d "/cache/00" or do{
		append_log("Trying to build cache for Squid");
		`$our_sudo /blocker/proxy/sbin/proxy -z`;
	};

	# Remove /cache/JUNK.
	-d "/cache/JUNK" and do{
		append_log("Trying to delete /cache/JUNK");

		my $kid = fork;
		if(!$kid){
			# Child runs this block
			setsid or die "Can't start a new session: $!";
    
			`$our_sudo_rm -rf /cache/JUNK`;

			exit;
		}
	};

	# Update portal page.
	update_login_page(1);

        #Update ssl files
        update_ssl_domains();
        update_safe_search();

	# Update urlcategories table.
	chk_urlcategories();

	# Restart and reload daemons.
	restart_all();
	reload_all();
}

#------------------------------------------------------
sub update_all{
	if($update_flags->{rc}){
		update_rc_conf();
		$update_flags->{rc} = 0;
	} 

	if($update_flags->{hosts}){
		update_hosts_conf();
		$update_flags->{hosts} = 0;
	}

	if($update_flags->{resolv}){
		update_resolv_conf();
		$update_flags->{resolv} = 0;
	}

	if($update_flags->{smb}){
		update_smb_conf();
		$update_flags->{smb} = 0;
	}

	if($update_flags->{squid}){
		update_squid_conf();
		$update_flags->{squid} = 0;
	}

	if($update_flags->{cachemgr}){
		update_cachemgr_conf();
		$update_flags->{cachemgr} = 0;
	}

	if($update_flags->{crontab}){
		update_crontab_conf();
		$update_flags->{crontab} = 0;
	}

	if($update_flags->{ntpd}){
		update_ntpd_conf();
		$update_flags->{ntpd} = 0;
	}

	if($update_flags->{windowsupdate}){
		update_windowsupdate_conf();
		$update_flags->{windowsupdate} = 0;
	}

	if($update_flags->{urlsvr}){
		update_urlsvr_conf();
		$update_flags->{urlsvr} = 0;
	}

	if($update_flags->{ssl_domains}){
		update_ssl_domains();
		$update_flags->{ssl_domains} = 0;
	}

	if($update_flags->{safe_search}){
		update_safe_search();
		$update_flags->{safe_search} = 0;
	}

	if($update_flags->{snmp}){
		update_snmp_conf();
		$update_flags->{snmp} = 0;
	} 
}

#------------------------------------------------------
sub reload_all{
	if($reload_flags->{squid}){
		append_log("Trying to reload proxy");

		if(time - $last_squid_reload > 60){
			`$our_sudo /blocker/proxy/sbin/proxy -k reconfigure`;

			$reload_flags->{squid} = 0;

			$last_squid_reload = time;

			append_log("Proxy reloaded");
		}
		else{
			append_log("We can reload squid.conf only once in a minute");
		}
	}

	if($reload_flags->{logger}){
		append_log("Trying to reload logger");

		`$our_sudo_pkill -HUP logger-pg`;

		$reload_flags->{logger} = 0;

		append_log("Logger reloaded");
	}
}

#------------------------------------------------------
sub stop_smb{
	`$our_sudo /usr/local/etc/rc.d/samba stop`;
	if(is_proc_alive("smbd") || is_proc_alive("winbindd") || is_proc_alive("nmbd")) {
		`$our_sudo_pkill smbd nmbd winbindd`;
	}
}

#------------------------------------------------------
sub restart_smb_with_repeat{
	my $rh_authpolicy = $dbh->selectrow_hashref("select * from authpolicy");
	my $enable_auth = $rh_authpolicy->{enable_auth} eq "TRUE" ? 1 : 0;
	my $enable_ntlm = $rh_authpolicy->{enable_ntlm} eq "TRUE" ? 1 : 0;
	my $ntdcname = trim($rh_authpolicy->{ntdcname});
	my $ntbkupdcname = trim($rh_authpolicy->{ntbkupdcname});
	my $ntusername = trim($rh_authpolicy->{ntusername});
	my $ntpassword = trim($rh_authpolicy->{ntpassword});
	my $ntdomname = trim($rh_authpolicy->{ntdomname});

	$ntdomname = uc($ntdomname);

	return unless $enable_auth and $enable_ntlm;

	for(1..10){
		$ntdcname and do{
			append_log("Trying to restart samba, attemp no. $_");

			stop_smb();
			sleep 1;

			my $res_text = `$our_sudo /usr/local/bin/net rpc join -S $ntdcname -U$ntusername%'$ntpassword' 2>&1`;
			append_log("restart_smb, $res_text");
			$? and do{
				append_log("restart_smb, Joining $ntdomname using $ntdcname failed");

				$ntbkupdcname and do{
					append_log("Trying to join $ntdomname using $ntbkupdcname");
				
					$res_text = `$our_sudo /usr/local/bin/net rpc join -S $ntbkupdcname -U$ntusername%'$ntpassword' 2>&1`;
					append_log("restart_smb, $res_text");
					$? and append_log("restart_smb, Joining $ntdomname using $ntbkupdcname failed");
				};

			};

			`$our_sudo /usr/local/etc/rc.d/samba start`;
			$? and do{
				append_log("restart_smb, Restarting samba failed");
				return;
			};
			sleep 1;

			append_log("Samba restarted");
		};

		# Check wbinfo -t result.
		my $res = "";
		if(is_winbindd_ok(\$res)){
			return;
		}

		append_err("wbinfo -t returned an error, trying it again");
	}
}

#------------------------------------------------------
sub restart_smb{
	my $rh_authpolicy = $dbh->selectrow_hashref("select * from authpolicy");
	my $enable_auth = $rh_authpolicy->{enable_auth} eq "TRUE" ? 1 : 0;
	my $enable_ntlm = $rh_authpolicy->{enable_ntlm} eq "TRUE" ? 1 : 0;
	my $ntdcname = trim($rh_authpolicy->{ntdcname});
	my $ntbkupdcname = trim($rh_authpolicy->{ntbkupdcname});
	my $ntusername = trim($rh_authpolicy->{ntusername});
	my $ntpassword = trim($rh_authpolicy->{ntpassword});
	my $ntdomname = trim($rh_authpolicy->{ntdomname});

	$ntdomname = uc($ntdomname);

	return unless $enable_auth and $enable_ntlm;

	$ntdcname and do{
		append_log("Trying to restart samba, attemp no. $_");

		stop_smb();
		sleep 1;

		my $res_text = `$our_sudo /usr/local/bin/net rpc join -S $ntdcname -U$ntusername%'$ntpassword' 2>&1`;
		append_log("restart_smb, $res_text");
		$? and do{
			append_log("restart_smb, Joining $ntdomname using $ntdcname failed");

			$ntbkupdcname and do{
				append_log("Trying to join $ntdomname using $ntbkupdcname");
			
				$res_text = `$our_sudo /usr/local/bin/net rpc join -S $ntbkupdcname -U$ntusername%'$ntpassword' 2>&1`;
				append_log("restart_smb, $res_text");
				$? and append_log("restart_smb, Joining $ntdomname using $ntbkupdcname failed");
			};

		};

		`$our_sudo /usr/local/etc/rc.d/samba start`;
		$? and do{
			append_log("restart_smb, Restarting samba failed");
			return;
		};
		sleep 1;

		append_log("Samba restarted");
	};

}

#------------------------------------------------------
sub check_gre0{
	if(`$our_sudo_ifconfig | /usr/bin/grep 10.20.30.40`){
		return 1;
	}
	return 0;
}

#------------------------------------------------------
sub restart_intercept{
	my $q = qq(
		select int_ip, transparentproxy, router_ip, tunnel_ip
		from networking
		);
	my($int_ip, $transparentproxy, $router_ip, $tunnel_ip) = $dbh->selectrow_array($q);
	if($router_ip and !$tunnel_ip){		# If there's just router_ip.
		$tunnel_ip = $router_ip;
	}

	`$our_sudo_ifconfig | /usr/bin/grep gre0` and do{
		append_log("restart_intercept, trying to destroy gre0");
		`$our_sudo_ifconfig gre0 destroy`;
	};
	if("TRUE" eq $transparentproxy){
		append_log("restart_intercept, trying to start intercept");

		if($tunnel_ip){
			`$our_sudo_ifconfig gre0 create`;
			
			my $cnt = 0;
			while(!check_gre0() and $cnt++ < 10){
				`$our_sudo_ifconfig gre0 $int_ip 10.20.30.40 netmask 255.255.255.255 link2 tunnel $int_ip $tunnel_ip up`;
				append_log("$our_sudo_ifconfig gre0 $int_ip 10.20.30.40 netmask 255.255.255.255 link2 tunnel $int_ip $tunnel_ip up");
				sleep 1;
			}
		}

		`$our_sudo_ipfwd start`;
		`$our_sudo_natd start`;

		append_log("restart_intercept, intercept started");
	}
	else{
		append_log("restart_intercept, trying to stop intercept");

		`$our_sudo_ipfwd stop`;
		`$our_sudo_natd stop`;

		append_log("restart_intercept, intercept stopped");
	}
}

#------------------------------------------------------
sub restart_all{
	
	open(LOCKFILE, "+>/var/run/overlord/overlord.lock") || die;
	flock(LOCKFILE, 2) || die;

	if($restart_flags->{network}){
		append_log("Trying to restart network");

		`$our_sudo /etc/rc.d/netif restart`;
		`$our_sudo /etc/rc.d/routing restart`;

		$restart_flags->{network} = 0;

		append_log("Network restarted");
		`$our_sudo /usr/local/bin/reghttpcfg.php`;
	}

	if($restart_flags->{smb}){
		restart_smb();

		$restart_flags->{smb} = 0;
	}

	if($restart_flags->{squid}){
		append_log("Trying to restart proxy");

		kill_proxy();
		`$our_proxy_start`;
		
		$restart_flags->{squid} = 0;

		append_log("Proxy restarted");
	}

	if($restart_flags->{ntpd}){
		append_log("Trying to restart ntpd");

		is_proc_alive("ntpd") and do{
			`$our_ntpd stop`;
			`$our_sudo_pkill ntpd`;
		};
		
		`$our_ntpd start`;
		
		$restart_flags->{ntpd} = 0;

		append_log("ntpd restarted");
	}

	if($restart_flags->{clamd}){
		append_log("Trying to restart clamd");

		is_proc_alive("clamd") and do{
			`$our_sudo_clamd stop`;
			`$our_sudo_pkill clamd`;
		};

		`$our_sudo_clamd start`;
		
		$restart_flags->{clamd} = 0;

		append_log("clamd restarted");
	}

	if($restart_flags->{intercept}){
		append_log("Trying to restart intercept");

		restart_intercept();
		
		$restart_flags->{intercept} = 0;

		append_log("intercept restarted");
	}

	if($restart_flags->{snmpd}){
		append_log("Trying to restart snmpd");
		unless(-e "$snmp_conf_file") {
			append_log("$snmp_conf_file missing, snmpd restarting aborted");			
		} else {
			`$our_sudo /usr/local/etc/rc.d/snmpd restart`;		
			$restart_flags->{snmpd} = 0;
			append_log("snmpd restarted");
		}
		
	}
	
	close(LOCKFILE);
}

#------------------------------------------------------
sub stop_all{
	
	if($stop_flags->{smb}){
		append_log("Trying to stop samba");

		stop_smb();

		$stop_flags->{smb} = 0;

		append_log("Samba stoped");
	}

	if($stop_flags->{snmpd}){
		append_log("Trying to stop snmpd");

		sudo_pkill("snmpd");
		
		$stop_flags->{snmpd} = 0;

		append_log("snmpd stoped");
	}
	
}

#------------------------------------------------------
sub check_db{
	my $cnt = $dbh->selectrow_array("select count(*) from networking");
	if($cnt != 1){
		append_log("Data number in networking: $cnt");
		return 0;
	}

	$cnt = $dbh->selectrow_array("select count(*) from policies");
	if($cnt < 3){
		append_log("Data number in policies: $cnt");
		return 0;
	}

	$cnt = $dbh->selectrow_array("select count(*) from groups");
	if($cnt < 2){
		append_log("Data number in groups: $cnt");
		return 0;
	}

	return 1;
}

#------------------------------------------------------
sub check_all{
	
	my $rh = check_proc_alive("proxy", "icapsvr", "logger-pg", "diasvr.pl", "urlsvr", "snmpd", "clamd");

	unless($rh->{"proxy"}){
		append_log("Trying to start proxy");

		`$our_proxy_start`;

		append_log("proxy started");
	}

	unless($rh->{"icapsvr"}){
		append_log("Trying to start icapsvr");
		
                my $env_prefix="";
                if ( -e "$icapsvr_conf_file")
                {
                        unless (-z "$icapsvr_conf_file")
                        {
                                my $buf = trim(read_text_file_arrayref($icapsvr_conf_file));
                                print "\nd[$buf]\n";
                                for my $line(@$buf){
                                        $line=trim($line);
                                        if ($line=="") {
                                                next
                                        }
                                        $env_prefix="env MALLOC_OPTIONS='".$line."'";
                                        last;
                                }

                        }
                }

                `$env_prefix /blocker/bin/icapsvr --daemon`;
                #`$env_prefix /blocker/bin/icapsvr -v --loglevel 255 --daemon`;
                #`env MALLOC_OPTIONS='7h' /blocker/bin/icapsvr --daemon`; #to disable mem cache

		append_log("icapsvr started [$env_prefix]");
	}

	unless($rh->{"logger-pg"}){
		append_log("Trying to start logger-pg");
		
		`/blocker/bin/logger-pg --daemon`;

		append_log("logger-pg started");
	}

	unless($rh->{"diasvr.pl"}){
		append_log("Trying to start diasvr.pl");
		
		`/blocker/bin/diasvr.pl > /dev/null &`;

		append_log("diasvr.pl started");
	}

	unless($rh->{"urlsvr"}){
		append_log("Trying to start urlsvr");
		
		`/blocker/bin/urlsvr > /dev/null &`;

		append_log("urlsvr started");
	}

	if(!$rh->{"snmpd"} and is_snmpd_enabled()){
		append_log("Trying to start snmpd");
		unless(-e "$snmp_conf_file") {
			append_log("$snmp_conf_file missing, snmpd starting aborted");
			
		} else {
			`$our_sudo /usr/local/etc/rc.d/snmpd restart`;
			append_log("snmpd started");
		}

		
	}

	unless($rh->{"clamd"}){
		my $rh_filtering = $dbh->selectrow_hashref("select avscan from filtering");
		my $avscan = $rh_filtering->{avscan} eq "TRUE" ? 1 : 0;
		if ($avscan) {
			append_log("Trying to start clamd");
			
			`$our_sudo_clamd start`;
		}
	}
}

#------------------------------------------------------
sub stop_daemons{
	
	append_log("Trying to stop proxy");
	kill_proxy();

	append_log("Trying to stop icapsvr");
	my $cnt = 0;
	while($cnt++ < 5 and pkill("icapsvr")){
		sleep 1;
	}

	append_log("Trying to stop logger");
	$cnt = 0;
	while($cnt++ < 5 and pkill("logger-pg")){
		sleep 1;
	}

	append_log("Trying to stop urlsvr");
	$cnt = 0;
	while($cnt++ < 5 and pkill("urlsvr")){
		sleep 1;
	}

	append_log("Trying to stop diasvr.pl");
	kill_diasvr();

	append_log("Trying to stop snmpd");
	sudo_pkill("snmpd");

	`$our_sudo_ifconfig | /usr/bin/grep gre0` and do{
		append_log("Trying to destroy gre0");
		`$our_sudo_ifconfig gre0 destroy`;
	};

	append_log("Trying to stop clamd");
	is_proc_alive("clamd") and do{
		`$our_sudo_clamd stop`;
		`$our_sudo_pkill clamd`;
	};
}

#------------------------------------------------------
sub gd_quit_event{
	stop_daemons();
	die "died with stop option.";
}

#------------------------------------------------------
sub gd_preconfig{
	# Must be redefined.
}

#------------------------------------------------------
sub gd_usage{
	print
qq(Usage: ./overlord.pl [ -f ] { start | stop restart | help }
 -f              Run in the foreground (don`t detach)
 start           Starts a new overlord.pl if there isn`t one running already
 stop            Stops a running overlord.pl
 restart         Stops a running overlord.pl if one is running.  Starts a new one.
 help            Display this usage info
);
}

#------------------------------------------------------
sub get_yyyymmdd{
	return strftime("%Y%m%d", localtime(time));
}

#------------------------------------------------------
sub gd_run{
	# Set environment variables.
	$ENV{PATH} .= ":/usr/local/bin";

	append_log("Started");

	# Waitng for PostgreSQL started.
	while(1){
		-e "/tmp/.s.PGSQL.5432" and last;

		append_log("Waitng for PostgreSQL started");
		sleep 1;
	}
	sleep 1;

	# Reverse conf.
	
	
	while(!init_globals()){
		sleep 1;
	}

	
	unless(check_db()){
		append_err_die("Invalid DB");
	}

	
	reverse_conf();

	# Init conf and restart some daemons.
	
	init_conf();
	
	
	restart_smb();
	
	# To setup firewall rules.
	
	restart_intercept();

	my $cnt = 0;
	my $diakey_update_time = get_yyyymmdd();
	
	while(1){
		if($cnt++ % 5 == 0){
			# Start daemons.
			#append_log("ML:check_all");
			check_all();
		}

		# Diakey update for diasvr.pl
		# daily routine job.
		if(get_yyyymmdd() ne $diakey_update_time){
			`/blocker/bin/diaclt.pl '/A updatediakey'`;
			$diakey_update_time = get_yyyymmdd();
			append_log("diakey update attempted");
		}

		unless(init_globals()){
			sleep 10;
			next;
		}

		check_update_time("networking") and do{
			$update_flags->{rc} = 1;
			$update_flags->{hosts} = 1;
			$update_flags->{resolv} = 1;
			$update_flags->{squid} = 1;
			$update_flags->{cachemgr} = 1;
			$reload_flags->{logger} = 1;
			$restart_flags->{intercept} = 1;
		};

		check_update_time("staticroutes") and do{
			$update_flags->{rc} = 1;
		};

		check_update_time("authpolicy") and do{
			$update_flags->{rc} = 1;
			$update_flags->{hosts} = 1;
			$update_flags->{smb} = 1;
			$update_flags->{squid} = 1;
			$update_flags->{windowsupdate} = 1;
			$restart_flags->{smb} = 1;
		};

		check_update_time("filtering") and do{
			$update_flags->{rc} = 1;
			$update_flags->{squid} = 1;
		};

		check_update_time("policyflags") and do{
			$update_flags->{safe_search} = 1;
			$update_flags->{squid} = 1;
		};

		check_update_time("cache") and do{
			$update_flags->{rc} = 1;
			$update_flags->{squid} = 1;
			$update_flags->{cachemgr} = 1;
			$restart_flags->{squid} = 1;
			$update_flags->{urlsvr} = 1;
		};

		check_update_time("proxy") and do{
			$restart_flags->{squid} = 1;
		};

		check_update_time("urlglobalhandling") and do{
			$update_flags->{squid} = 1;
		};

		check_update_time("ldapservers") and do{
			$update_flags->{crontab} = 1;
		};

		check_update_time("reportscheduling") and do{
			$update_flags->{crontab} = 1;
		};

		check_update_time("alerts") and do{
			$update_flags->{crontab} = 1;
		};

		check_update_time("datetime") and do{
			$update_flags->{rc} = 1;
			$update_flags->{ntpd} = 1;
		};

		check_update_time("exports") and do{
			$reload_flags->{logger} = 1;
		};

		check_update_time("backup") and do{
			$update_flags->{crontab} = 1;
		};

		check_update_time("policysafesearch") and do{
			$update_flags->{safe_search} = 1;
		};

		check_update_time("ssl_domains") and do{
			$update_flags->{ssl_domains} = 1;
		};


		check_update_time("urlcategories") and do{
			`/bin/pkill -SIGUSR1 urlsvr`;
		};

		check_update_time("urlscustom") and do{
			`/bin/pkill -SIGUSR1 urlsvr`;
		};


		check_update_time("snmp") and do{
			$update_flags->{rc} = 1;
			$update_flags->{snmp} = 1;
			$update_flags->{crontab} = 1;
			#xlog("ML:snmp & rc updating");
		};

		# These are just actions not from table changes.
		check_update_time("action_system_update") and do{
			append_log("Trying to action_system_update now");
			$update_flags->{rc} = 1;
			$update_flags->{hosts} = 1;
			$update_flags->{resolv} = 1;
			$update_flags->{squid} = 1;
			$update_flags->{cachemgr} = 1;
			$update_flags->{crontab} = 1;
			$update_flags->{snmp} = 1;
			$reload_flags->{logger} = 1;

			
		};

		check_update_time("action_rebuild_cache") and do{
			append_log("Trying to rebuild cache");

			my $rc = rebuild_cache();
			if($rc == 0){
				append_log("Rebuilding cache finished");
			}
			else{
				append_log("Rebuilding cache failed, response code = $rc");
			}
		};

		check_update_time("action_shutdown") and do{
			append_log("Trying to shutdown");

			stop_daemons();
			`$our_sudo_shutdown`;

			exit(0);
		};

		check_update_time("action_reboot") and do{
			append_log("Trying to reboot");

			stop_daemons();
			`$our_sudo_reboot`;

			exit(0);
		};

		check_update_time("action_restore_conf_tables") and do{
			append_log("Trying to restore conf tables");

			stop_daemons();

			my @args = get_update_time_args("action_restore_conf_tables");
			my $filename = shift @args;
			restore_conf_tables($dbh, $filename);

			check_all();
		};

		check_update_time("action_update_login_page") and do{
			append_log("Trying to update login page");

			my @args = get_update_time_args("action_update_login_page");
			my $id = shift @args;
			update_login_page($id);
		};

		check_update_time("action_cloud_only") and do{
			append_log("Trying to update urlsvr.cfg with cloud_only option");
			my @args = get_update_time_args("action_cloud_only");
			my $val = shift @args;
			update_urlsvr_conf($val);
		};
		
		
		update_all();
		
		reload_all();
		
		restart_all();
		
		stop_all();

		sleep 2;
	}
};

#------------------------------------------------------
# Main.
newdaemon(
	pidfile => "/var/run/overlord/overlord.pid",
	logpriority => "local5.info"
);

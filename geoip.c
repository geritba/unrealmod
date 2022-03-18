/* Copyright (C) All Rights Reserved
** Unauthorised copying of this file, via any medium is strictly prohibited
** Written by Gottem <support@gottem.nl>
** Website: https://u4shop.gottem.nl
** License: https://u4shop.gottem.nl/license.txt
*/

/*
** Build with (from <Unreal source dir>):
**    export EXLIBS="-lmaxminddb"
**    make
**    make install
*/

#include "unrealircd.h"

#include <maxminddb.h>

#define MYCONF "geoip"
#define SNOMASK_GEOIP 'g'
#define UMODE_DENY 0
#define UMODE_ALLOW 1

#define mmdb_cleanup(x, y) \
	do { \
		if((y)) MMDB_close(mmdb); \
		if((x)) free(x); \
	} while(0)

#define CheckAPIError(apistr, apiobj) \
	do { \
		if(!(apiobj)) { \
			config_error("A critical error occurred on %s for %s: %s", (apistr), MOD_HEADER.name, ModuleGetErrorStr(modinfo->handle)); \
			return MOD_FAILED; \
		} \
	} while(0)

typedef struct t_geoip geo;
struct t_geoip {
	char *cc;
	geo *next;
};

typedef struct t_geoipexcept geoexcept;
struct t_geoipexcept {
	char *ip;
	geoexcept *next;
};

typedef enum {
	CT_ALLOW = 0,
	CT_UNKNOWN = 1,
	CT_BLOCK = 2,
} ct; 

int geoip_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int geoip_configposttest(int *errs);
int geoip_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int geoip_prelocalconnect(Client *client);
unsigned short int is_geoexcept(Client *client);
int geoip_checkem(Client *client);
int geoip_ripperoni(Client *client, char *opermsg, char *usermsg, unsigned short int forceopermsg, ct conntype);
static int geoip_checksnomask(Client *client, int what);

long SNO_GEOIP = 0L;

struct {
	geo *blocklist;
	geoexcept *exceptlist;
	int blockcount;
	int exceptcount;

	char *db; 
	char *denymsg; 
	unsigned short int allowunknown; 
	unsigned short int notifyopers; 
	unsigned short int softfail; 
	unsigned short int exemptwebsocket; 

	unsigned short int got_db;
	unsigned short int got_denymsg;
	unsigned short int got_allowunknown;
	unsigned short int got_notifyopers;
	unsigned short int got_softfail;
	unsigned short int got_exemptwebsocket;
} muhcfg;

ModuleHeader MOD_HEADER = {
	"third/geoip", 
	"2.0", 
	"Deny connections based on IP location data", 
	"Gottem", 
	"unrealircd-5", 
};

MOD_TEST() {
	muhcfg.blocklist = NULL;
	muhcfg.exceptlist = NULL;
	muhcfg.blockcount = 0;
	muhcfg.exceptcount = 0;

	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, geoip_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, geoip_configposttest);
	return MOD_SUCCESS;
}

MOD_INIT() {
	CheckAPIError("SnomaskAdd(SNO_GEOIP)", SnomaskAdd(modinfo->handle, SNOMASK_GEOIP, geoip_checksnomask, &SNO_GEOIP));

	MARK_AS_GLOBAL_MODULE(modinfo);

	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, geoip_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_PRE_LOCAL_CONNECT, -999, geoip_prelocalconnect);
	return MOD_SUCCESS;
}

MOD_LOAD() {
	return MOD_SUCCESS; 
}

MOD_UNLOAD() {
	if(muhcfg.blocklist) {
		geo *gEntry;
		while((gEntry = muhcfg.blocklist) != NULL) {
			muhcfg.blocklist = muhcfg.blocklist->next;
			safe_free(gEntry->cc);
			safe_free(gEntry);
		}
	}
	if(muhcfg.exceptlist) {
		geoexcept *geEntry;
		while((geEntry = muhcfg.exceptlist) != NULL) {
			muhcfg.exceptlist = muhcfg.exceptlist->next;
			safe_free(geEntry->ip);
			safe_free(geEntry);
		}
	}
	safe_free(muhcfg.db);
	safe_free(muhcfg.denymsg);
	return MOD_SUCCESS; 
}

int geoip_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
	int errors = 0; 
	ConfigEntry *cep, *cep2; 
	char dbbuf[256]; 

	if(type != CONFIG_MAIN)
		return 0; 

	if(!ce || !ce->ce_varname)
		return 0;

	if(strcmp(ce->ce_varname, MYCONF))
		return 0;

	for(cep = ce->ce_entries; cep; cep = cep->ce_next) {
		if(!cep->ce_varname) {
			config_error("%s:%i: blank %s item", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF); 
			errors++; 
			continue; 
		}

		if(strcmp(cep->ce_varname, "block") && strcmp(cep->ce_varname, "exceptions")) {
			if(!cep->ce_vardata || !strlen(cep->ce_vardata)) {
				config_error("%s:%i: blank %s value", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF); 
				errors++; 
				continue; 
			}
		}

		if(!strcmp(cep->ce_varname, "db")) {
			if(muhcfg.got_db)
				config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			muhcfg.got_db = 1;
			snprintf(dbbuf, sizeof(dbbuf), "%s/%s", SCRIPTDIR, cep->ce_vardata);
			if(access(dbbuf, R_OK) == -1) {
				config_error("%s:%i: DB file %s doesn't exist or isn't readable by the IRCd user", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, dbbuf); 
				errors++; 
			}
			continue;
		}

		if(!strcmp(cep->ce_varname, "denymsg")) {
			if(muhcfg.got_denymsg)
				config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			muhcfg.got_denymsg = 1;
			continue;
		}

		if(!strcmp(cep->ce_varname, "allowunknown")) {
			if(muhcfg.got_allowunknown)
				config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			muhcfg.got_allowunknown = 1;
			continue;
		}

		if(!strcmp(cep->ce_varname, "notifyopers")) {
			if(muhcfg.got_notifyopers)
				config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			muhcfg.got_notifyopers = 1;
			continue;
		}

		if(!strcmp(cep->ce_varname, "softfail")) {
			if(muhcfg.got_softfail)
				config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			muhcfg.got_softfail = 1;
			continue;
		}

		if(!strcmp(cep->ce_varname, "exemptwebsocket")) {
			if(muhcfg.got_exemptwebsocket)
				config_warn("%s:%i: duplicate directive %s::%s, will use the last encountered one", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			muhcfg.got_exemptwebsocket = 1;
			continue;
		}

		if(!strcmp(cep->ce_varname, "block")) {
			for(cep2 = cep->ce_entries; cep2; cep2 = cep2->ce_next) {
				if(!cep2->ce_varname || !strlen(cep2->ce_varname)) {
					config_error("%s:%i: blank %s::%s item", cep2->ce_fileptr->cf_filename, cep2->ce_varlinenum, MYCONF, cep->ce_varname); 
					errors++; 
					continue; 
				}
				muhcfg.blockcount++;
			}
			continue;
		}

		if(!strcmp(cep->ce_varname, "exceptions")) {
			for(cep2 = cep->ce_entries; cep2; cep2 = cep2->ce_next) {
				if(!cep2->ce_varname || !strlen(cep2->ce_varname)) {
					config_error("%s:%i: blank %s::%s item", cep2->ce_fileptr->cf_filename, cep2->ce_varlinenum, MYCONF, cep->ce_varname); 
					errors++; 
					continue; 
				}
				muhcfg.exceptcount++;
			}
			continue;
		}

		config_warn("%s:%i: unknown item %s::%s", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname); 
	}

	*errs = errors;
	return errors ? -1 : 1; 
}

int geoip_configposttest(int *errs) {
	int errors = 0;

	if(!muhcfg.blockcount) {
		config_error("No (valid) entries found for %s::block found (might be empty/misconfigured)", MYCONF); 
		errors++; 
	}

	if(!muhcfg.got_db) {
		config_error("No path found for %s::db", MYCONF); 
		errors++; 
	}

	if(!muhcfg.got_denymsg && !errors) 
		muhcfg.denymsg = strdup("Denied connection");
	if(!muhcfg.got_notifyopers)
		muhcfg.notifyopers = 1; 
	if(!muhcfg.got_allowunknown)
		muhcfg.allowunknown = 0; 
	if(!muhcfg.got_softfail)
		muhcfg.softfail = 0;
	if(!muhcfg.got_exemptwebsocket)
		muhcfg.exemptwebsocket = 0;

	*errs = errors;
	return errors ? -1 : 1;
}

int geoip_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
	ConfigEntry *cep, *cep2; 
	geo *gLast; 
	geo **gEntry = &muhcfg.blocklist; 
	geoexcept *geLast;
	geoexcept **geEntry = &muhcfg.exceptlist;

	if(type != CONFIG_MAIN)
		return 0; 

	if(!ce || !ce->ce_varname)
		return 0;

	if(strcmp(ce->ce_varname, MYCONF))
		return 0;

	for(cep = ce->ce_entries; cep; cep = cep->ce_next) {
		if(!cep->ce_varname)
			continue; 

		if(!strcmp(cep->ce_varname, "db")) {
			safe_strdup(muhcfg.db, cep->ce_vardata);
			convert_to_absolute_path(&muhcfg.db, SCRIPTDIR);
			continue;
		}

		if(!strcmp(cep->ce_varname, "denymsg")) {
			safe_strdup(muhcfg.denymsg, cep->ce_vardata);
			continue;
		}

		if(!strcmp(cep->ce_varname, "allowunknown")) {
			muhcfg.allowunknown = config_checkval(cep->ce_vardata, CFG_YESNO);
			continue;
		}

		if(!strcmp(cep->ce_varname, "notifyopers")) {
			muhcfg.notifyopers = config_checkval(cep->ce_vardata, CFG_YESNO);
			continue;
		}

		if(!strcmp(cep->ce_varname, "softfail")) {
			muhcfg.softfail = config_checkval(cep->ce_vardata, CFG_YESNO);
			continue;
		}

		if(!strcmp(cep->ce_varname, "exemptwebsocket")) {
			muhcfg.exemptwebsocket = config_checkval(cep->ce_vardata, CFG_YESNO);
			continue;
		}

		if(!strcmp(cep->ce_varname, "block")) {
			gLast = NULL;
			for(cep2 = cep->ce_entries; cep2; cep2 = cep2->ce_next) {
				size_t cclen = sizeof(char) * (strlen(cep2->ce_varname) + 1);

				*gEntry = safe_alloc(sizeof(geo));

				(*gEntry)->cc = safe_alloc(cclen);

				strncpy((*gEntry)->cc, cep2->ce_varname, cclen);

				if(gLast)
					gLast->next = *gEntry;

				gLast = *gEntry;
				gEntry = &(*gEntry)->next;
			}
			continue;
		}

		if(!strcmp(cep->ce_varname, "exceptions")) {
			geLast = NULL;
			for(cep2 = cep->ce_entries; cep2; cep2 = cep2->ce_next) {
				size_t iplen = sizeof(char) * (strlen(cep2->ce_varname) + 1);

				*geEntry = safe_alloc(sizeof(geo));

				(*geEntry)->ip = safe_alloc(iplen);

				strncpy((*geEntry)->ip, cep2->ce_varname, iplen);

				if(geLast)
					geLast->next = *geEntry;

				geLast = *geEntry;
				geEntry = &(*geEntry)->next;
			}
			continue;
		}
	}
	return 1; 
}

int geoip_prelocalconnect(Client *client) {
	return geoip_checkem(client); 
}

unsigned short int is_geoexcept(Client *client) {
	geoexcept *geEntry; 
	for(geEntry = muhcfg.exceptlist; geEntry; geEntry = geEntry->next) {
		if(match_user(geEntry->ip, client, MATCH_CHECK_IP | MATCH_CHECK_REAL_HOST))
			return 1;
	}
	return 0;
}

int geoip_checkem(Client *client) {
	geo *gEntry; 
	MMDB_s *mmdb; 
	MMDB_lookup_result_s res; 
	MMDB_entry_data_s entry_data; 
	int ret_mmdb, ret_gai; 
	char cc[8]; 
	char cn[128]; 
	char opermsg[BUFSIZE]; 
	size_t cclen, cnlen; 

	if(IsULine(client))
		return HOOK_CONTINUE;

	if(muhcfg.exemptwebsocket && IsWebsocket(client))
		return HOOK_CONTINUE;

	if(!client->ip)
		return geoip_ripperoni(client, "Fatal error: client has no value for IP (client->ip == NULL)", NULL, 1, CT_ALLOW);

	if((mmdb = (MMDB_s *)calloc(1, sizeof(MMDB_s))) == NULL) 
		return geoip_ripperoni(client, "Fatal error: unable to allocate memory for walking through the MMDB structure", NULL, 1, CT_ALLOW);

	if((ret_mmdb = MMDB_open(muhcfg.db, MMDB_MODE_MMAP, mmdb)) != MMDB_SUCCESS) { 
		snprintf(opermsg, sizeof(opermsg), "Fatal error when opening DB file: [%d] %s", ret_mmdb, MMDB_strerror(ret_mmdb));
		mmdb_cleanup(mmdb, 0); 
		return geoip_ripperoni(client, opermsg, NULL, 1, CT_ALLOW);
	}

	if(mmdb->file_size <= 0) {
		snprintf(opermsg, sizeof(opermsg), "Fatal error: unexpected DB file size (%ld bytes)", mmdb->file_size);
		mmdb_cleanup(mmdb, 0);
		return geoip_ripperoni(client, opermsg, NULL, 1, CT_ALLOW);
	}

	res = MMDB_lookup_string(mmdb, client->ip, &ret_gai, &ret_mmdb); 
	if(ret_gai != 0) { 
		snprintf(opermsg, sizeof(opermsg), "Error when looking up address information (getaddrinfo()): [%d] %s", ret_gai, gai_strerror(ret_gai));
		mmdb_cleanup(mmdb, 1); 
		return geoip_ripperoni(client, opermsg, muhcfg.denymsg, 0, CT_UNKNOWN);
	}
	if(ret_mmdb != MMDB_SUCCESS) { 
		snprintf(opermsg, sizeof(opermsg), "MMDB error when looking up IP: [%d] %s", ret_mmdb, MMDB_strerror(ret_mmdb));
		mmdb_cleanup(mmdb, 1);
		return geoip_ripperoni(client, opermsg, muhcfg.denymsg, 0, CT_UNKNOWN);
	}

	if(!res.found_entry) {
		mmdb_cleanup(mmdb, 1);
		return geoip_ripperoni(client, "Lookup error: IP not found in DB", muhcfg.denymsg, 0, CT_UNKNOWN);
	}

	if((ret_mmdb = MMDB_get_value(&res.entry, &entry_data, "country", "iso_code", NULL)) != MMDB_SUCCESS || !entry_data.has_data) {
		snprintf(opermsg, sizeof(opermsg), "Unable to get country \002ISO code\002 for IP: [%d] %s", ret_mmdb, MMDB_strerror(ret_mmdb));
		mmdb_cleanup(mmdb, 1);
		return geoip_ripperoni(client, opermsg, muhcfg.denymsg, 0, CT_UNKNOWN);
	}

	cclen = entry_data.data_size + 1;
	snprintf(cc, (cclen > sizeof(cc) ? sizeof(cc) : cclen), "%s", entry_data.utf8_string);

	if((ret_mmdb = MMDB_get_value(&res.entry, &entry_data, "country", "names", "en", NULL)) != MMDB_SUCCESS || !entry_data.has_data) {
		sendto_snomask_global(SNO_GEOIP, "[geoip] [warn] Unable to get \002country name\002 for IP: [%d] %s", ret_mmdb, MMDB_strerror(ret_mmdb));
		snprintf(cn, sizeof(cn), "UNKNOWN");
	}
	else {
		cnlen = entry_data.data_size + 1;
		snprintf(cn, (cnlen > sizeof(cn) ? sizeof(cn) : cnlen), "%s", entry_data.utf8_string);
	}

	mmdb_cleanup(mmdb, 1); 

	for(gEntry = muhcfg.blocklist; gEntry; gEntry = gEntry->next) {
		if(strncasecmp(cc, gEntry->cc, strlen(gEntry->cc)) == 0) { 
			snprintf(opermsg, sizeof(opermsg), "Client matched blocked country \002%s\002 (%s)", cn, cc);
			return geoip_ripperoni(client, opermsg, muhcfg.denymsg, 0, CT_BLOCK);
		}
	}
	return HOOK_CONTINUE;
}

int geoip_ripperoni(Client *client, char *opermsg, char *usermsg, unsigned short int forceopermsg, ct conntype) {
	int ret;
	unsigned short int softfail, excepted;
	char omsg[BUFSIZE];

	softfail = (muhcfg.softfail && conntype != CT_ALLOW ? 1 : 0); 
	excepted = 0;
	if(conntype == CT_UNKNOWN && muhcfg.allowunknown)
		softfail = 0;
	else if((conntype != CT_ALLOW || softfail) && (excepted = is_geoexcept(client)))
		softfail = 0;
	snprintf(omsg, sizeof(omsg), "[geoip] %s%s", (softfail ? "SOFTFAIL: " : ""), opermsg);

	ret = HOOK_CONTINUE; 
	if(!softfail && !excepted) {
		if(conntype == CT_UNKNOWN) { 
			if(!muhcfg.allowunknown)
				ret = HOOK_DENY; 
		}
		else if(conntype == CT_BLOCK) 
			ret = HOOK_DENY;

		if(conntype != CT_BLOCK && ret == HOOK_CONTINUE)
			ircsnprintf(omsg, sizeof(omsg), "%s -- allowing connection", omsg);
		else if(ret != HOOK_CONTINUE)
			ircsnprintf(omsg, sizeof(omsg), "%s -- denying connection", omsg);
	}
	if(excepted)
		ircsnprintf(omsg, sizeof(omsg), "%s -- allowing whitelisted connection", omsg);

	if(strcmp(client->user->realhost, client->ip)) 
		ircsnprintf(omsg, sizeof(omsg), "%s (%s!%s@%s[%s])", omsg, client->name, client->user->username, client->user->realhost, client->ip);
	else
		ircsnprintf(omsg, sizeof(omsg), "%s (%s!%s@%s)", omsg, client->name, client->user->username, client->user->realhost);

	if(forceopermsg || muhcfg.notifyopers) 
		sendto_snomask_global(SNO_FCLIENT, "%s", omsg);
	ircd_log(LOG_ERROR, "%s", omsg);

	if(ret == HOOK_DENY)
		exit_client(client, NULL, usermsg);
	return ret;
}

static int geoip_checksnomask(Client *client, int what) {
	if(!MyUser(client) || IsULine(client) || ValidatePermissionsForPath("geoip", client, NULL, NULL, NULL))
		return UMODE_ALLOW;
	return UMODE_DENY;
}

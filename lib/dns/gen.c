/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

 /* $Id: gen.c,v 1.25 1999/10/05 19:50:09 halley Exp $ */

#include <config.h>

#include <sys/types.h>

#include <ctype.h>
#include <dirent.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#define FROMTEXTDECL "dns_rdataclass_t rdclass, dns_rdatatype_t type, isc_lex_t *lexer, dns_name_t *origin, isc_boolean_t downcase, isc_buffer_t *target"
#define FROMTEXTARGS "rdclass, type, lexer, origin, downcase, target"
#define FROMTEXTCLASS "rdclass"
#define FROMTEXTTYPE "type"
#define FROMTEXTDEF "use_default = ISC_TRUE"

#define TOTEXTDECL "dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, isc_buffer_t *target"
#define TOTEXTARGS "rdata, tctx, target"
#define TOTEXTCLASS "rdata->rdclass"
#define TOTEXTTYPE "rdata->type"
#define TOTEXTDEF "use_default = ISC_TRUE"

#define FROMWIREDECL "dns_rdataclass_t rdclass, dns_rdatatype_t type, isc_buffer_t *source, dns_decompress_t *dctx, isc_boolean_t downcase, isc_buffer_t *target"
#define FROMWIREARGS "rdclass, type, source, dctx, downcase, target"
#define FROMWIRECLASS "rdclass"
#define FROMWIRETYPE "type"
#define FROMWIREDEF "use_default = ISC_TRUE"

#define TOWIREDECL "dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target"
#define TOWIREARGS "rdata, cctx, target"
#define TOWIRECLASS "rdata->rdclass"
#define TOWIRETYPE "rdata->type"
#define TOWIREDEF "use_default = ISC_TRUE"

#define FROMSTRUCTDECL "dns_rdataclass_t rdclass, dns_rdatatype_t type, void *source, isc_buffer_t *target"
#define FROMSTRUCTARGS "rdclass, type, source, target"
#define FROMSTRUCTCLASS "rdclass"
#define FROMSTRUCTTYPE "type"
#define FROMSTRUCTDEF "use_default = ISC_TRUE"

#define TOSTRUCTDECL "dns_rdata_t *rdata, void *target, isc_mem_t *mctx"
#define TOSTRUCTARGS "rdata, target, mctx"
#define TOSTRUCTCLASS "rdata->rdclass"
#define TOSTRUCTTYPE "rdata->type"
#define TOSTRUCTDEF "use_default = ISC_TRUE"

#define FREESTRUCTDECL "void *source"
#define FREESTRUCTARGS "source"
#define FREESTRUCTCLASS "common->rdclass"
#define FREESTRUCTTYPE "common->rdtype"
#define FREESTRUCTDEF NULL

#define COMPAREDECL "dns_rdata_t *rdata1, dns_rdata_t *rdata2"
#define COMPAREARGS "rdata1, rdata2"
#define COMPARECLASS "rdata1->rdclass"
#define COMPARETYPE "rdata1->type"
#define COMPAREDEF "use_default = ISC_TRUE"

#define ADDITIONALDATADECL \
	"dns_rdata_t *rdata, dns_additionaldatafunc_t add, void *arg"
#define ADDITIONALDATAARGS "rdata, add, arg"
#define ADDITIONALDATACLASS "rdata->rdclass"
#define ADDITIONALDATATYPE "rdata->type"
#define ADDITIONALDATADEF "use_default = ISC_TRUE"

#define DIGESTDECL \
	"dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg"
#define DIGESTARGS "rdata, digest, arg"
#define DIGESTCLASS "rdata->rdclass"
#define DIGESTTYPE "rdata->type"
#define DIGESTDEF "use_default = ISC_TRUE"

char copyright[] =
"/*\n\
 * Copyright (C) 1998%s Internet Software Consortium.\n\
 *\n\
 * Permission to use, copy, modify, and distribute this software for any\n\
 * purpose with or without fee is hereby granted, provided that the above\n\
 * copyright notice and this permission notice appear in all copies.\n\
 *\n\
 * THE SOFTWARE IS PROVIDED \"AS IS\" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS\n\
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES\n\
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE\n\
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL\n\
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR\n\
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS\n\
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS\n\
 * SOFTWARE.\n\
 */\n\
\n\
 /* THIS FILE IS AUTOMATICALLY GENERATED: DO NOT EDIT */\n\
\n";

struct cc {
	struct cc *next;
	int rdclass;
	char classname[11];
} *classes;

struct tt {
	struct tt *next;
	int rdclass;
	int type;
	char classname[11];
	char typename[11];
	char dirname[256];		/* XXX Should be max path length */
} *types;

char *	upper(char *);
char *	funname(char *, char *);
void	doswitch(char *, char *, char *, char *, char *, char *);
void	dodecl(char *, char *, char *);
void	add(int, char *, int, char *, char *);
void	sd(int, char *, char *, char);

char *
upper(char *s) {
	static char buf[11];
	char *b = buf;
	char c;

	while ((c = *s++)) {
		
		*b++ = islower(c) ? toupper(c) : c;
	}
	*b = '\0';
	return (buf);
}

char *
funname(char *s, char *buf) {
	char *b = buf;
	char c;

	while ((c = *s++)) {
		*b++ = (c == '-') ? '_' : c;
	}
	*b = '\0';
	return (buf);
}

void
doswitch(char *name, char *function, char *args,
	 char *tsw, char *csw, char *res)
{
	struct tt *tt;
	int first = 1;
	int lasttype = 0;
	int subswitch = 0;
	char buf1[11], buf2[11];
	char *result = " result =";

	if (res == NULL)
		result = "";

	for (tt = types; tt != NULL ; tt = tt->next) {
		if (first) {
			fprintf(stdout, "\n#define %s \\\n", name);
			fprintf(stdout, "\tswitch (%s) { \\\n" /*}*/, tsw);
			first = 0;
		}
		if (tt->type != lasttype && subswitch) {
			if (res == NULL)
				fprintf(stdout, "\t\tdefault: break; \\\n");
			else
				fprintf(stdout,
					"\t\tdefault: %s; break; \\\n", res);
			fputs(/*{*/ "\t\t} \\\n", stdout);
			fputs("\t\tbreak; \\\n", stdout);
			subswitch = 0;
		}
		if (tt->rdclass && tt->type != lasttype) {
			fprintf(stdout, "\tcase %d: switch (%s) { \\\n" /*}*/,
				tt->type, csw);
			subswitch = 1;
		}
		if (tt->rdclass == 0)
			fprintf(stdout,
				"\tcase %d:%s %s_%s(%s); break;",
				tt->type, result, function,
				funname(tt->typename, buf1), args);
		else
			fprintf(stdout,
			        "\t\tcase %d:%s %s_%s_%s(%s); break;",
				tt->rdclass, result, function, 
				funname(tt->classname, buf1),
				funname(tt->typename, buf2), args);
		fputs(" \\\n", stdout);
		lasttype = tt->type;
	}
	if (subswitch) {
		if (res == NULL)
			fprintf(stdout, "\t\tdefault: break; \\\n");
		else 
			fprintf(stdout, "\t\tdefault: %s; break; \\\n", res);
		fputs(/*{*/ "\t\t} \\\n", stdout);
		fputs("\t\tbreak; \\\n", stdout);
	}
	if (first) {
		if (res == NULL)
			fprintf(stdout, "\n#define %s\n", name);
		else
			fprintf(stdout, "\n#define %s %s;\n", name, res);
	} else {
		if (res == NULL)
			fprintf(stdout, "\tdefault: break; \\\n");
		else
			fprintf(stdout, "\tdefault: %s; break; \\\n", res);
		fputs(/*{*/ "\t}\n", stdout);
	}
}

void
dodecl(char *type, char *function, char *args) {
	struct tt *tt;
	char buf1[11], buf2[11];

	fputs("\n", stdout);
	for (tt = types; tt ; tt = tt->next)
		if (tt->rdclass)
			fprintf(stdout,
				"static inline %s %s_%s_%s(%s);\n",
				type, function,
				funname(tt->classname, buf1),
				funname(tt->typename, buf2), args);
		else
			fprintf(stdout,
				"static inline %s %s_%s(%s);\n",
				type, function, 
				funname(tt->typename, buf1), args);
}

void
add(int rdclass, char *classname, int type, char *typename, char *dirname) {
	struct tt *newtt = (struct tt *)malloc(sizeof *newtt);
	struct tt *tt, *oldtt;
	struct cc *newcc;
	struct cc *cc, *oldcc;

	if (newtt == NULL)
		exit(1);

	newtt->next = NULL;
	newtt->rdclass = rdclass;
	newtt->type = type;
	strcpy(newtt->classname, classname);
	strcpy(newtt->typename, typename);
	strcpy(newtt->dirname, dirname);

	tt = types;
	oldtt = NULL;

	while ((tt != NULL) && (tt->type < type)) {
		oldtt = tt;
		tt = tt->next;
	}

	while ((tt != NULL) && (tt->type == type) && (tt->rdclass < rdclass)) {
		if (strcmp(tt->typename, typename) != 0)
			exit(1);
		oldtt = tt;
		tt = tt->next;
	}

	if ((tt != NULL) && (tt->type == type) && (tt->rdclass == rdclass))
		exit(1);

	newtt->next = tt;
	if (oldtt != NULL)
		oldtt->next = newtt;
	else
		types = newtt;

	/* do a class switch for this type */
	 
	if (rdclass == 0)
		return;

	newcc = (struct cc *)malloc(sizeof *newcc);
	newcc->rdclass = rdclass;
	strcpy(newcc->classname, classname);
	cc = classes;
	oldcc = NULL;
	
	while ((cc != NULL) && (cc->rdclass < rdclass)) {
		oldcc = cc;
		cc = cc->next;
	}

	if ((cc != NULL) && cc->rdclass == rdclass) {
		free((char *)newcc);
		return;
	}

	newcc->next = cc;
	if (oldcc != NULL)
		oldcc->next = newcc;
	else
		classes = newcc;
}

void
sd(int rdclass, char *classname, char *dir, char filetype) {
	char buf[sizeof "0123456789_65535.h"];
	char fmt[sizeof "%10[-0-9a-z]_%d.h"];
	DIR *d;
	int type;
	char typename[11];
	struct dirent *dp;

	if ((d = opendir(dir)) == NULL)
		return;

	sprintf(fmt,"%s%c", "%10[-0-9a-z]_%d.", filetype);
	while ((dp = readdir(d)) != NULL) {
		if (sscanf(dp->d_name, fmt, typename, &type) != 2)
			continue;
		if ((type > 65535) || (type < 0))
			continue;

		sprintf(buf, "%s_%d.%c", typename, type, filetype);
		if (strcmp(buf, dp->d_name) != 0)
			continue;
		add(rdclass, classname, type, typename, dir);
	}
	closedir(d);
}

int
main(int argc, char **argv) {
	DIR *d;
	char buf[256];			/* XXX Should be max path length */
	char srcdir[256];		/* XXX Should be max path length */
	int rdclass;
	char classname[11];
	struct dirent *dp;
	struct tt *tt;
	struct cc *cc;
	struct tm *tm;
	time_t now;
	char year[11];
	int lasttype;
	int code = 1;
	int class_enum = 0;
	int type_enum = 0;
	int structs = 0;
	int c;
	char buf1[11];
	char filetype = 'c';
	FILE *fd;
	char *prefix = NULL;
	char *suffix = NULL;

	strcpy(srcdir, "");
	while ((c = getopt(argc, argv, "cits:P:S:")) != -1)
		switch (c) {
		case 'c':
			code = 0;
			type_enum = 0;
			class_enum = 1;
			filetype = 'c';
			structs = 0;
			break;
		case 't':
			code = 0;
			class_enum = 0;
			type_enum = 1;
			filetype = 'c';
			structs = 0;
			break;
		case 'i':
			code = 0;
			class_enum = 0;
			type_enum = 0;
			structs = 1;
			filetype = 'h';
			break;
		case 's':
			sprintf(srcdir, "%s/", optarg);
			break;
		case 'P':
			prefix = optarg;
			break;
		case 'S':
			suffix = optarg;
			break;
		case '?':
			exit(1);
		}

	sprintf(buf, "%srdata", srcdir);
	if ((d = opendir(buf)) == NULL)
		exit(1);

	while ((dp = readdir(d)) != NULL) {
		if (sscanf(dp->d_name, "%10[0-9a-z]_%d",
			   classname, &rdclass) != 2)
			continue;
		if ((rdclass > 65535) || (rdclass < 0))
			continue;

		sprintf(buf, "%srdata/%s_%d", srcdir, classname, rdclass);
		if (strcmp(buf + 6 + strlen(srcdir), dp->d_name) != 0)
			continue;
		sd(rdclass, classname, buf, filetype);
	}
	closedir(d);
	sprintf(buf, "%srdata/generic", srcdir);
	sd(0, "", buf, filetype);

	if (time(&now) != -1) {
		if ((tm = localtime(&now)) != NULL && tm->tm_year > 98)
			sprintf(year, "-%d", tm->tm_year + 1900);
		else
			year[0] = 0;
	} else
		year[0] = 0;

	fprintf(stdout, copyright, year);

	if (code) {
		dodecl("dns_result_t", "fromtext", FROMTEXTDECL);
		dodecl("dns_result_t", "totext", TOTEXTDECL);
		dodecl("dns_result_t", "fromwire", FROMWIREDECL);
		dodecl("dns_result_t", "towire", TOWIREDECL);
		dodecl("int", "compare", COMPAREDECL);
		dodecl("dns_result_t", "fromstruct", FROMSTRUCTDECL);
		dodecl("dns_result_t", "tostruct", TOSTRUCTDECL);
		dodecl("void", "freestruct", FREESTRUCTDECL);
		dodecl("dns_result_t", "additionaldata", ADDITIONALDATADECL);
		dodecl("dns_result_t", "digest", DIGESTDECL);

		doswitch("FROMTEXTSWITCH", "fromtext", FROMTEXTARGS,
			 FROMTEXTTYPE, FROMTEXTCLASS, FROMTEXTDEF);
		doswitch("TOTEXTSWITCH", "totext", TOTEXTARGS,
			 TOTEXTTYPE, TOTEXTCLASS, TOTEXTDEF);
		doswitch("FROMWIRESWITCH", "fromwire", FROMWIREARGS,
			 FROMWIRETYPE, FROMWIRECLASS, FROMWIREDEF);
		doswitch("TOWIRESWITCH", "towire", TOWIREARGS,
			 TOWIRETYPE, TOWIRECLASS, TOWIREDEF);
		doswitch("COMPARESWITCH", "compare", COMPAREARGS,
			  COMPARETYPE, COMPARECLASS, COMPAREDEF);
		doswitch("FROMSTRUCTSWITCH", "fromstruct", FROMSTRUCTARGS,
			  FROMSTRUCTTYPE, FROMSTRUCTCLASS, FROMSTRUCTDEF);
		doswitch("TOSTRUCTSWITCH", "tostruct", TOSTRUCTARGS,
			  TOSTRUCTTYPE, TOSTRUCTCLASS, TOSTRUCTDEF);
		doswitch("FREESTRUCTSWITCH", "freestruct", FREESTRUCTARGS,
			  FREESTRUCTTYPE, FREESTRUCTCLASS, FREESTRUCTDEF);
		doswitch("ADDITIONALDATASWITCH", "additionaldata",
			 ADDITIONALDATAARGS, ADDITIONALDATATYPE,
			 ADDITIONALDATACLASS, ADDITIONALDATADEF);
		doswitch("DIGESTSWITCH", "digest",
			 DIGESTARGS, DIGESTTYPE,
			 DIGESTCLASS, DIGESTDEF);

		fprintf(stdout, "\n#define TYPENAMES%s\n",
			types != NULL ? " \\" : "");

		lasttype = 0;
		for (tt = types; tt != NULL ; tt = tt->next)
			if (tt->type != lasttype)
				fprintf(stdout, "\t{ %d, \"%s\", 0 },%s\n",
					lasttype = tt->type,
					upper(tt->typename),
					tt->next != NULL ? " \\" : "");

		fputs("\n", stdout);
		fprintf(stdout, "\n#define CLASSNAMES%s\n",
			classes != NULL ? " \\" : "");

		for (cc = classes; cc != NULL; cc = cc->next)
			fprintf(stdout, "\t{ %d, \"%s\", 0 },%s\n",
				cc->rdclass, upper(cc->classname),
				cc->next != NULL ? " \\" : "");


		fputs("\n", stdout);
		for (tt = types; tt != NULL ; tt = tt->next)
			fprintf(stdout, "#include \"%s/%s_%d.c\"\n",
				tt->dirname, tt->typename, tt->type);
	} else if (type_enum) {
		fprintf(stdout, "#ifndef TYPEENUM\n");
		fprintf(stdout, "#define TYPEENUM%s\n",
			types != NULL ? " \\" : "");

		lasttype = 0;
		for (tt = types; tt != NULL ; tt = tt->next)
			if (tt->type != lasttype)
				fprintf(stdout, "\t dns_rdatatype_%s = %d,%s\n",
					funname(tt->typename, buf1),
					lasttype = tt->type,
					tt->next != NULL ? " \\" : "");
		fprintf(stdout, "#endif /* TYPEENUM */\n");
	} else if (class_enum) {
		fprintf(stdout, "#ifndef CLASSENUM\n");
		fprintf(stdout, "#define CLASSENUM%s\n",
			classes != NULL ? " \\" : "");

		for (cc = classes; cc != NULL; cc = cc->next)
			fprintf(stdout, "\t dns_rdataclass_%s = %d,%s\n",
				funname(cc->classname, buf1),
				cc->rdclass,
				cc->next != NULL ? " \\" : "");
		fprintf(stdout, "#endif /* CLASSENUM */\n");
	} else if (structs) {
		if (prefix != NULL) {
			if ((fd = fopen(prefix,"r")) != NULL) {
				while (fgets(buf, sizeof buf, fd) != NULL)
					fputs(buf, stdout);
				fclose(fd);
			}
		}
		for (tt = types; tt != NULL ; tt = tt->next) {
			sprintf(buf, "%s/%s_%d.h",
				tt->dirname, tt->typename, tt->type);
			if ((fd = fopen(buf,"r")) != NULL) {
				while (fgets(buf, sizeof buf, fd) != NULL)
					fputs(buf, stdout);
				fclose(fd);
			}
		}
		if (suffix != NULL) {
			if ((fd = fopen(suffix,"r")) != NULL) {
				while (fgets(buf, sizeof buf, fd) != NULL)
					fputs(buf, stdout);
				fclose(fd);
			}
		}
	}

	if (ferror(stdout) != 0)
		exit(1);

	return (0);
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <string.h>
#include <stdlib.h>
#include "opt.h"
#include "lcsync.h"

int opt_set_str(opt_t *opt, int *argc, char **argv[])
{
	(*argc)--;
	*(char **)opt->var = *(++(*argv));
	return 0;
}

int opt_set_int(opt_t *opt, int *argc, char **argv[])
{
	(*argc)--;
	*(int *)opt->var = strtod(*(++(*argv)), NULL);
	return 0;
}

int opt_set_true(opt_t *opt)
{
	*(int *)opt->var = 1;
	return 0;
}

static int opt_longoptcmp(char *olong, const char *arg)
{
	if (!strncmp(arg, "--", 2)) {
		if  (!strcmp(arg+2, olong)) {
			return 1;
		}
	}
	return 0;
}

static int opt_valid(opt_parser_t *parser, const char *arg, opt_t **opt)
{
	for (int i = 0; i < parser->optc; i++) {
		*opt = &parser->optv[i];
		if (arg[0] == '-') {
			if (arg[1] == (*opt)->oshort)
				return 1;
			if (opt_longoptcmp((*opt)->olong, arg))
				return 1;
		}
	}
	return 0;
}

int opt_parse(opt_parser_t *parser, int *argc, char **argv[])
{
	int rc = 0;
	opt_t *opt;
	progname = *(*argv)++;
	(*argc)--;
	while ((*argc) && **argv) {
		if (**argv[0] != '-') return 0; /* nec tamen consumebatur! */
		if (!opt_valid(parser, *argv[0], &opt)) return -1;
		if (opt->f != NULL) {
			opt->f(opt, argc, argv);
		}
		else {
			switch (opt->type) {
			case OTYPE_BOOL:
				if ((rc = opt_set_true(opt)))
					return rc;
				break;
			case OTYPE_INT:
				if ((rc = opt_set_int(opt, argc, argv)))
					return rc;
				break;
			case OTYPE_STR:
				if ((rc = opt_set_str(opt, argc, argv)))
					return rc;
				break;
			}
		}
		(*argc)--;
		(*argv)++;
	}
	return 0;
}

int opt_new(opt_parser_t *parser, opt_t *opt)
{
	opt_t *o;
	for (int i = 0; i < parser->optc; i++) {
		o = &parser->optv[i];
		if (!o->var) {
			o->var = opt->var;
			o->type = opt->type;
			o->oshort = opt->oshort;
			/* set custom setter, if available
			 * delay working out other type functions until opt_parse()
			 * as option may never be used */
			if (opt->f) o->f = opt->f;
			strcpy(o->olong, opt->olong);
			return 0;
		}
	}
	return -1;
}

void opt_free(opt_parser_t *parser)
{
	free(parser);
}

opt_parser_t *opt_init(int optc)
{
	opt_parser_t *parser;
	if (!optc || !(parser = calloc(1, sizeof(opt_parser_t) + sizeof(opt_t) * optc)))
		return NULL;
	parser->optc = optc;
	return parser;
}

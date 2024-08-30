/*
 * Copyright © 2024 konsolebox
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the “Software”), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/limits.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DSBA_NAME_VALUE_PREFIX "DBUS_SESSION_BUS_ADDRESS=unix:path="
#define DSBA_NAME_VALUE_MAX_LENGTH 35 + PATH_MAX
#define DSBA_VALUE_OFFSET 25

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const char *xdg_runtime_dir, *current_dsba;
	char dsba_name_value[DSBA_NAME_VALUE_MAX_LENGTH + 1];
	int silent, quiet, override, r;

	(void)argc; (void)argv;

	silent = (flags & PAM_SILENT) == PAM_SILENT;
	quiet = override = 0;

	for (; argc-- > 0; ++argv) {
		if (strcmp(*argv, "quiet") == 0)
			quiet = 1;
		else if (strcmp(*argv, "override") == 0)
			override = 1;
		else
			pam_syslog(pamh, LOG_ERR, "Unknown option: %s", *argv);
	}

	xdg_runtime_dir = pam_getenv(pamh, "XDG_RUNTIME_DIR");

	if (xdg_runtime_dir == NULL || *xdg_runtime_dir != '/') {
		if (!silent)
			pam_syslog(pamh, LOG_ERR, "Failed to get value of XDG_RUNTIME_DIR or is invalid");

		return PAM_SESSION_ERR;
	}

	if (snprintf(dsba_name_value, DSBA_NAME_VALUE_MAX_LENGTH, DSBA_NAME_VALUE_PREFIX "%s/bus",
			xdg_runtime_dir) >= (int) DSBA_NAME_VALUE_MAX_LENGTH) {
		if (!silent)
			pam_syslog(pamh, LOG_ERR, "Generated path exceeds PATH_MAX (%u)", PATH_MAX);

		return PAM_SESSION_ERR;
	}

	current_dsba = pam_getenv(pamh, "DBUS_SESSION_BUS_ADDRESS");

	if (current_dsba != NULL && *current_dsba != '\0') {
		if (strncmp(current_dsba, &dsba_name_value[DSBA_VALUE_OFFSET],
				(size_t) PATH_MAX + 1) == 0) {
			if (!silent && !quiet)
				pam_syslog(pamh, LOG_INFO,
						"DBUS_SESSION_BUS_ADDRESS is already set to the correct value: %s",
						current_dsba);

			return PAM_SUCCESS;
		} else if (override) {
			if (!silent && !quiet)
				pam_syslog(pamh, LOG_INFO, "Overriding current DBUS_SESSION_BUS_ADDRESS value: %s",
						current_dsba);
		} else {
			if (!silent)
				pam_syslog(pamh, LOG_ERR, \
						"DBUS_SESSION_BUS_ADDRESS is already set to a different value: %s",
						current_dsba);

			return PAM_SESSION_ERR;
		}
	}

	if (!silent && !quiet)
		pam_syslog(pamh, LOG_INFO, "Assigning %s", dsba_name_value);

	if ((r = pam_putenv(pamh, dsba_name_value)) != PAM_SUCCESS) {
		if (!silent)
			pam_syslog(pamh, LOG_ERR, "Failed to define DBUS_SESSION_BUS_ADDRESS in env: %s",
					pam_strerror(pamh, r));

		return PAM_SESSION_ERR;
	}

	return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_IGNORE;
}

#define define_should_not_be_called_function(BASIC_NAME) \
	int pam_sm_##BASIC_NAME(pam_handle_t *pamh, int flags, int argc, const char **argv) \
	{ \
		(void)pamh; (void)flags; (void)argc; (void)argv; \
		pam_syslog(pamh, LOG_ERR, "Module does not provide '%s' function", \
				#BASIC_NAME); \
		return PAM_SERVICE_ERR; \
	}

define_should_not_be_called_function(authenticate)
define_should_not_be_called_function(setcred)
define_should_not_be_called_function(acct_mgmt)
define_should_not_be_called_function(chauthtok)

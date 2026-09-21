#include <darling/emulation/xnu_syscall/bsd/impl/misc/csops.h>

#include <stdint.h>
#include <sys/codesign.h>
#include <sys/errno.h>
#include <strings.h>
#include <string.h>

#include <darling/emulation/conversion/duct_errno.h>

/*
 * Chrome base/mac/process_requirement.cc calls CS_OPS_TEAMID and
 * CS_OPS_VALIDATION_CATEGORY. ENOSYS is not in its unsigned/ad-hoc set
 * (EINVAL/ENOENT), so GatherMetrics then SecCodeCopyGuestWithAttributes
 * and an NSMutableDictionary nil setObject abort the browser.
 *
 * Darling has no real csblob. Report an unsigned-but-well-formed process:
 * STATUS stays CS_VALID (ad-hoc), TEAMID is ENOENT, VALIDATION_CATEGORY is
 * CS_VALIDATION_CATEGORY_NONE. That is what XNU returns for ad-hoc.
 */
#ifndef CS_OPS_VALIDATION_CATEGORY
#define CS_OPS_VALIDATION_CATEGORY 17
#endif
#ifndef CS_VALIDATION_CATEGORY_INVALID
#define CS_VALIDATION_CATEGORY_INVALID 0
#define CS_VALIDATION_CATEGORY_NONE 10
#endif

__attribute__((used)) static const char csops_teamid_v1[] = "csops_teamid_v1";

long sys_csops(int pid, unsigned int ops, void* useraddr, size_t usersize) {
	int ret = 0;

	(void)pid;
	(void)csops_teamid_v1;

	switch (ops) {
		case CS_OPS_STATUS: {
			if (useraddr == NULL || usersize < sizeof(uint32_t)) {
				return -ERANGE;
			}
			*(uint32_t*)useraddr = CS_VALID;
		} break;

		case CS_OPS_TEAMID: {
			/*
			 * XNU: 8-byte fake blob header then the team-id C string.
			 * No team id (ad-hoc / unsigned) -> ENOENT. Chrome treats
			 * ENOENT and EINVAL as expected and uses an empty team id.
			 */
			return -ENOENT;
		}

		case CS_OPS_VALIDATION_CATEGORY: {
			if (useraddr == NULL || usersize < sizeof(uint32_t)) {
				return -ERANGE;
			}
			*(uint32_t*)useraddr = CS_VALIDATION_CATEGORY_NONE;
		} break;

		case CS_OPS_CDHASH: {
			if (useraddr == NULL) {
				return -EINVAL;
			}
			memset(useraddr, 0, usersize);
			return -ENOENT;
		}

		case CS_OPS_BLOB:
		case CS_OPS_ENTITLEMENTS_BLOB:
		case CS_OPS_IDENTITY: {
			if (useraddr == NULL) {
				return -EINVAL;
			}
			memset(useraddr, 0, usersize);
			/*
			 * PidDiskRep probes sizeof(BlobCore) and expects ERANGE
			 * plus a length. A zero success made it throw
			 * errSecCSNoSuchCode (C++, caught). EINVAL matches an
			 * ad-hoc process with no blob.
			 */
			return -ENOENT;
		}

		default: {
			ret = -ENOSYS;
		} break;
	}

	return ret;
}

long sys_csops_audittoken(int pid, unsigned int ops, void* useraddr, size_t usersize, audit_token_t* audit_token) {
	(void)audit_token;
	return sys_csops(pid, ops, useraddr, usersize);
}

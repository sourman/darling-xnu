#ifndef DARLING_CONVERSION_XATTR_NAME
#define DARLING_CONVERSION_XATTR_NAME

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>

#define XATTR_USER_PREFIX "user."
#define XATTR_USER_PREFIX_LEN 5
#define XATTR_LINUX_NAME_MAX 256

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memmove(void* dest, const void* src, __SIZE_TYPE__ n);

static inline int xattr_has_user_prefix(const char* name)
{
	return name != NULL
		&& name[0] == 'u' && name[1] == 's' && name[2] == 'e'
		&& name[3] == 'r' && name[4] == '.';
}

static inline const char* xattr_name_to_linux(const char* name, char* buf, size_t buflen)
{
	size_t nlen;
	size_t i;

	if (name == NULL)
		return NULL;
	if (xattr_has_user_prefix(name))
		return name;

	nlen = 0;
	while (name[nlen] != '\0')
		nlen++;

	if (XATTR_USER_PREFIX_LEN + nlen + 1 > buflen)
		return NULL;

	for (i = 0; i < XATTR_USER_PREFIX_LEN; i++)
		buf[i] = XATTR_USER_PREFIX[i];
	memcpy(buf + XATTR_USER_PREFIX_LEN, name, nlen + 1);
	return buf;
}

static inline int xattr_ret_linux_to_bsd(int ret)
{
	int err;

	if (ret >= 0)
		return ret;

	err = -ret;
	if (err == LINUX_ENODATA || err == LINUX_EOPNOTSUPP)
		return -ENOATTR;

	return errno_linux_to_bsd(ret);
}

static inline long xattr_list_strip_user(char* buf, long ret)
{
	char* src;
	char* dst;
	char* end;

	if (ret <= 0 || buf == NULL)
		return ret;

	src = buf;
	dst = buf;
	end = buf + ret;

	while (src < end) {
		size_t len = 0;
		const char* name;
		size_t outlen;

		while (src + len < end && src[len] != '\0')
			len++;

		name = src;
		outlen = len;
		if (len >= XATTR_USER_PREFIX_LEN && xattr_has_user_prefix(src)) {
			name = src + XATTR_USER_PREFIX_LEN;
			outlen = len - XATTR_USER_PREFIX_LEN;
		}

		if (dst != name)
			memmove(dst, name, outlen);
		dst[outlen] = '\0';
		dst += outlen + 1;
		src += len + 1;
	}

	return dst - buf;
}

#endif // DARLING_CONVERSION_XATTR_NAME

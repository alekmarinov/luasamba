#include <stdio.h>
#include <lua.h>
#include <lauxlib.h>
#include <libsmbclient.h>
#include <malloc.h>
#include <string.h>
#include <errno.h>

#ifndef LUASAMBA_API
#define LUASAMBA_API	extern
#endif

#define LUASAMBA_LIBNAME "samba"
#define SMB_DIR_HANDLE "smbDirT"
#define SMB_FILE_HANDLE "smbFileT"

/* wrap values of arbitrary type */
union luaValueT
{
	int nval;
	double dval;
	const char* sval;
	void* ptr;
};

/* push correctly luaValue to Lua stack */
static void pushLuaValueT(lua_State* L, int t, union luaValueT v)
{
	switch (t)
	{
		case LUA_TNIL: lua_pushnil(L); break;
		case LUA_TBOOLEAN: lua_pushboolean(L, v.nval); break;
		case LUA_TFUNCTION: 
		case LUA_TUSERDATA: lua_rawgeti(L, LUA_REGISTRYINDEX, v.nval); break;
		case LUA_TNUMBER: lua_pushnumber(L, v.dval); break;
		case LUA_TSTRING: lua_pushstring(L, v.sval); break;
		default: luaL_error(L, "invalid type %s\n", lua_typename(L, t));
	}
}

/* Samba object wrapper type */
typedef struct
{
	int sh;
	lua_State* L;
	union luaValueT udata;
	int utype;
} sambaT;

#define LUA_FUNCTION_SIZE	50

/* auth callback global reference */
static lua_State* _L;
static int smb_auth_ref=0;
static union luaValueT smb_auth_param={0};
static int smb_auth_param_type=LUA_TNIL;

void smbc_get_auth_data_callback(
	const char *srv,
	const char *shr,
	char *wg, int wglen,
	char *un, int unlen,
	char *pw, int pwlen)
{
	if (_L)
	{
		lua_rawgeti(_L, LUA_REGISTRYINDEX, smb_auth_ref);
		pushLuaValueT(_L, smb_auth_param_type, smb_auth_param);
		lua_pushstring(_L, srv);
		lua_pushstring(_L, shr);
		lua_call(_L, 3, 3);
		strncpy(pw, lua_tostring(_L, -1), pwlen-1);
		strncpy(un, lua_tostring(_L, -2), unlen-1);
		strncpy(wg, lua_tostring(_L, -3), wglen-1);
		lua_pop(_L, 3);
	}
}

int lsamba_init(lua_State* L)
{
	int result;
	_L=L;
	luaL_checktype(L, 1, LUA_TFUNCTION);   /* accept only function argument used for samba authentications */
	lua_pushvalue(L, 1);                                
	smb_auth_ref=luaL_ref(L, LUA_REGISTRYINDEX);  /* get reference to the lua object in registry */
	if (lua_gettop(L)>1)
	{
		smb_auth_param_type=lua_type(L, 2);
		switch (smb_auth_param_type)        /* handle user parameter of arbitrary type */
		{
			case LUA_TTABLE:
			case LUA_TUSERDATA:
			case LUA_TFUNCTION:
				lua_pushvalue(L, 2);
				smb_auth_param.nval=luaL_ref(L, LUA_REGISTRYINDEX);
			break;
			case LUA_TNUMBER:
				smb_auth_param.dval=lua_tonumber(L, 2);
			break;
			case LUA_TBOOLEAN:
				smb_auth_param.nval=lua_toboolean(L, 2);
			break;		
			case LUA_TSTRING:
				smb_auth_param.sval=lua_tostring(L, 2);
			break;
			case LUA_TNIL:
				smb_auth_param.nval=0;
			break;
			default:
				lua_pushnil(L);
				lua_pushstring(L, "luasamba: not supported type for parameter 2");
				return 2;
			break;
		}
	}

	result=smbc_init(smbc_get_auth_data_callback, 0 /* disable debug */);
	if (0>result && ENOMEM==errno)
	{
		lua_pushnil(L);
		lua_pushstring(L, "luasamba: out of memory");
		return 2;
	} 
	else if (0>result && ENOENT==errno)
	{
		lua_pushnil(L);
		lua_pushstring(L, "luasamba: the smb.conf file would not load");
		return 2;
	}
	lua_pushboolean(L, 1);
	return 1;
}

/* Access samba handle object from the Lua stack at specified position  */
static int* tosmbdirhandle (lua_State *L, int cindex, const char* debug_info) 
{
	int* c=(int*)luaL_checkudata(L, cindex, SMB_DIR_HANDLE);
	if (!c) luaL_argerror(L, cindex, "luasamba: invalid directory handle");
	if (!(*c)) 
	{
		lua_pushfstring(L, "luasamba (%s): attempt to use closed directory handle", debug_info);
		lua_error(L);
	}
	return c;
}

static int* tosmbfilehandle (lua_State *L, int cindex, const char* debug_info) 
{
	int* c=(int*)luaL_checkudata(L, cindex, SMB_FILE_HANDLE);
	if (!c) luaL_argerror(L, cindex, "luasamba: invalid file handle");
	if (!(*c)) 
	{
		lua_pushfstring(L, "luasamba (%s): attempt to use closed file handle", debug_info);
		lua_error(L);
	}
	return c;
}

int lsamba_opendir(lua_State* L)
{
	const char* url;
	int* c;
	url=lua_tostring(L, 1);
	luaL_checktype(L, 1, LUA_TSTRING);
	c=(int*)lua_newuserdata(L, sizeof(int));
	*c=smbc_opendir(url);
	if (0>*c)
	{
		lua_pushnil(L);
		switch (errno)
		{
		case EACCES: lua_pushstring(L, "luasamba: permission denied"); break;
		case EINVAL: lua_pushstring(L, "luasamba: a NULL file/URL was passed, or "\
			"the URL would not parse, or was of incorrect form or smbc_init not called"); break;
		case ENOENT: lua_pushstring(L, "luasamba: url does not exist"); break;
		case ENOMEM: lua_pushstring(L, "luasamba: insufficient memory to complete the operation"); break;
		case ENOTDIR: lua_pushstring(L, "luasamba: name is not a directory"); break;
		case EPERM: lua_pushstring(L, "luasamba: the workgroup could not be found"); break;
		case ENODEV: lua_pushstring(L, "luasamba: the workgroup or server could not be found"); break;
		case ECONNREFUSED: lua_pushstring(L, "luasamba: connection refused"); break;
		case ENETUNREACH: lua_pushstring(L, "luasamba: Network is unreachable"); break;
		default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}
	/* set metatable to directory handle object */
	luaL_getmetatable(L, SMB_DIR_HANDLE);
	lua_setmetatable(L, -2);
	return 1;
}

int lsamba_readdir(lua_State* L)
{
	struct smbc_dirent* dirent;
	int dh=*tosmbdirhandle(L, 1, "lsamba_readdir");
	dirent=smbc_readdir(dh);
	if (dirent)
	{
		lua_pushlstring(L, dirent->name, dirent->namelen);

		/* 
			smbc_type is any of the following:
			SMBC_WORKGROUP=1, SMBC_SERVER=2, SMBC_FILE_SHARE=3, SMBC_PRINTER_SHARE=4, 
			SMBC_COMMS_SHARE=5, SMBC_IPC_SHARE=6, SMBC_DIR=7, SMBC_FILE=8, SMBC_LINK=9 
		*/
 
		lua_pushnumber(L, (double)dirent->smbc_type);
		lua_pushlstring(L, dirent->comment, dirent->commentlen);
		return 3;
	} 
	else
	{
		if (EBADF==errno)
		{
			lua_pushnil(L);
			lua_pushstring(L, "luasamba: invalid directory handle");
			return 2;
		} 
		else if (ENOENT==errno)
		{
			lua_pushnil(L);
			lua_pushstring(L, "luasamba: smbc_init() failed or has not been called");
			return 2;
		} /* else end of directory is reached */
	}
	return 0;
}

int lsamba_closedir(lua_State* L)
{
	int* dh=(int*)luaL_checkudata(L, 1, SMB_DIR_HANDLE);
	if (*dh)
	{
		if (0>smbc_closedir(*dh))
		{
			if (EBADF==errno)
			{
				lua_pushnil(L);
				lua_pushstring(L, "luasamba: invalid directory handle");
				return 2;
			}
		}
		*dh=0;
	}
	lua_pushboolean(L, 1);
	return 1;
}

int lsamba_createdir(lua_State* L)
{
	int result;
	luaL_checktype(L, 1, LUA_TSTRING); /* directory url */
	luaL_checktype(L, 2, LUA_TNUMBER); /* permissions */

	if (0>smbc_mkdir(lua_tostring(L, 1), (int)lua_tonumber(L, 2)))
	{
		lua_pushnil(L);
		switch (errno)
		{
			case EEXIST:
				lua_pushstring(L, "luasamba: directory url already exists");
			break;
			case EACCES:
				lua_pushstring(L, "luasamba: The parent directory does not allow write permission to the process, or one of the directories");
			break;
			case ENOENT:
				lua_pushstring(L, "luasamba: A directory component in pathname does not exist");
			break;
			case EINVAL:
				lua_pushstring(L, "luasamba: NULL url passed or smbc_init not called");
			break;
			case ENOMEM:
				lua_pushstring(L, "luasamba: Insufficient memory was available.");
			break;
			default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}
	lua_pushboolean(L, 1);
	return 1;
}

int lsamba_openfile(lua_State* L)
{
	int* c;
	luaL_checktype(L, 1, LUA_TSTRING); /* samba url (smb://host/share/file) */
	luaL_checktype(L, 2, LUA_TNUMBER); /* open mode */
	c=(int*)lua_newuserdata(L, sizeof(int));
	*c=smbc_open(lua_tostring(L, 1), (int)lua_tonumber(L, 2), (int)lua_tonumber(L, 3));
	if (0>*c)
	{
		lua_pushnil(L);
		switch (errno)
		{
		case EACCES: lua_pushstring(L, "luasamba: The requested access to the file is not allowed"); break;
		case EINVAL: lua_pushstring(L, "luasamba: if an invalid parameter passed,"\
			" like no file, or smbc_init not called"); break;
		case ENOENT: lua_pushstring(L, "luasamba: A directory component in pathname does not exist"); break;
		case ENOMEM: lua_pushstring(L, "luasamba: out of memory"); break;
		case ENOTDIR: lua_pushstring(L, "luasamba: A file on the path is not a directory"); break;
		case EPERM: lua_pushstring(L, "luasamba: the workgroup could not be found"); break;
		case ENODEV: lua_pushstring(L, "luasamba: The requested share does not exist"); break;
		case EEXIST: lua_pushstring(L, "luasamba: pathname already exists and O_CREAT and O_EXCL were used"); break;
		case EISDIR: lua_pushstring(L, "luasamba: pathname refers to a directory and the access requested involved writing"); break;
		default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}
	/* set metatable to directory handle object */
	luaL_getmetatable(L, SMB_FILE_HANDLE);
	lua_setmetatable(L, -2);
	return 1;
}

int lsamba_readfile(lua_State* L)
{
	void* buf;
	int fd, buf_size, nBytes;
	fd=*tosmbfilehandle(L, 1, "lsamba_readfile");
	luaL_checktype(L, 2, LUA_TNUMBER); /* buffer size */
	buf_size=(int)lua_tonumber(L, 2);
	buf=malloc(buf_size+1);
	nBytes = smbc_read(fd, buf, buf_size);
	if (nBytes > 0)
	{
		lua_pushlstring(L, (char*)buf, nBytes);
		free(buf);
		return 1;
	}
	free(buf);
	if (nBytes < 0)
	{
		lua_pushnil(L);
		switch (errno)
		{
		case EISDIR: lua_pushstring(L, "luasamba: fd refers to a directory"); break;
		case EBADF: lua_pushstring(L, "luasamba: fd is not a valid file descriptor or is not open for reading"); break;
		case EINVAL: lua_pushstring(L, "luasamba: fd is attached to an object which is unsuitable for reading, "\
			"or no buffer passed or smbc_init not called"); break;
		default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}

	/* nBytes == 0 -> eof reached */
	return 0;
}

int lsamba_writefile(lua_State* L)
{
	const char* buf;
	int size, fd;

	fd=*tosmbfilehandle(L, 1, "lsamba_writefile");
	luaL_checktype(L, 2, LUA_TSTRING); /* buffer */
	buf=lua_tostring(L, 2);
	size = lua_strlen(L, 2);
	size=smbc_write(fd, (void *)buf, size);
	if (0>size)
	{
		lua_pushnil(L);
		switch (errno)
		{
		case EISDIR: lua_pushstring(L, "luasamba: fd refers to a directory"); break;
		case EBADF: lua_pushstring(L, "luasamba: fd is not a valid file descriptor or is not open for writing"); break;
		case EINVAL: lua_pushstring(L, "luasamba: fd is attached to an object which is unsuitable for writing, "\
			"or no buffer passed or smbc_init not called"); break;
		default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}

	lua_pushnumber(L, (double)size);
	return 1;
}

int lsamba_closefile(lua_State* L)
{
	int* fd=(int*)luaL_checkudata(L, 1, SMB_FILE_HANDLE);
	if (*fd)
	{
		if (0>smbc_close(*fd))
		{
			lua_pushnil(L);
			switch (errno)
			{
			case EBADF: lua_pushstring(L, "luasamba: fd isn't a valid open file descriptor"); break;
			case EINVAL: lua_pushstring(L, "luasamba: smbc_init() failed or has not been called"); break;
			default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
			}
			return 2;
		}
		*fd=0;
	}
	lua_pushboolean(L, 1);
	return 1;
}

int lsamba_seekfile(lua_State* L)
{
	off_t result;
	int fd=*tosmbfilehandle(L, 1, "lsamba_seekfile");
	luaL_checktype(L, 2, LUA_TNUMBER); /* file offset */
	luaL_checktype(L, 3, LUA_TNUMBER); /* whence */

	if (0>(result=smbc_lseek(fd, (off_t)lua_tonumber(L, 2), (int)lua_tonumber(L, 3))))
	{
		lua_pushnil(L);
		switch (errno)
		{
		case EBADF: lua_pushstring(L, "luasamba: fd isn't a valid open file descriptor"); break;
		case EINVAL: lua_pushstring(L, "luasamba: whence is not a proper value or smbc_init not called."); break;
		default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}

	lua_pushnumber(L, (double)result);
	return 1;
}

int lsamba_filesize(lua_State* L)
{
	struct stat st;
	__off_t size=0;
	int fd=*tosmbfilehandle(L, 1, "lsamba_filesize");
	st.st_size=0;

	if (smbc_fstat(fd, &st) == 0)
	{
		size=st.st_size;
	} 
	else
	{
		lua_pushnil(L);
		switch (errno)
		{
		case EBADF: lua_pushstring(L, "luasamba: bad file descriptor"); break;
		case EACCES: lua_pushstring(L, "luasamba: permission denied"); break;
		case EINVAL: lua_pushstring(L, "luasamba: problems occurred in the underlying routines or smbc_init not called"); break;
		case ENOMEM: lua_pushstring(L, "luasamba: out of memory"); break;
		default: lua_pushfstring(L, "luasamba: error #%d", errno); break;
		}
		return 2;
	}
	lua_pushnumber(L, (double)size);
	return 1;
}

static const struct luaL_reg reg_luasamba_funcs[] =
{
	{"init", lsamba_init},
	{"opendir", lsamba_opendir},
	{"createdir", lsamba_createdir},
	{"openfile", lsamba_openfile},
	{0, 0}
};

static const struct luaL_reg reg_luasamba_dirmeths[] =
{
	{"readdir", lsamba_readdir},
	{"closedir", lsamba_closedir},
	{"__gc", lsamba_closedir},
	{0, 0}
};

static const struct luaL_reg reg_luasamba_filemeths[] =
{
	{"readfile", lsamba_readfile},
	{"writefile", lsamba_writefile},
	{"closefile", lsamba_closefile},
	{"seekfile", lsamba_seekfile},
	{"filesize", lsamba_filesize},	
	{"__gc", lsamba_closefile},
	{0, 0}
};

static void createmeta (lua_State *L, const char* metaname) 
{
	luaL_newmetatable(L, metaname);
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, -2);
	lua_rawset(L, -3);
}

/* Fast set table macro */
#define LUA_SET_TABLE(context, key_type, key, value_type, value) \
	lua_push##key_type(context, key); \
	lua_push##value_type(context, value); \
	lua_settable(context, -3);

/*
 * Assumes the table is on top of the stack.
 */
static void set_info (lua_State *L) 
{
	LUA_SET_TABLE(L, literal, "_COPYRIGHT", literal, "(C) 2003-2005 AVIQ Systems AG");
	LUA_SET_TABLE(L, literal, "_DESCRIPTION", literal, "luasamba binds smbclient library to Lua");
	LUA_SET_TABLE(L, literal, "_NAME", literal, "luasamba");
	LUA_SET_TABLE(L, literal, "_VERSION", literal, "1.0.0");

	/* entry type */
	LUA_SET_TABLE(L, literal, "WORKGROUP", number, SMBC_WORKGROUP);
	LUA_SET_TABLE(L, literal, "SERVER", number, SMBC_SERVER);
	LUA_SET_TABLE(L, literal, "FILE_SHARE", number, SMBC_FILE_SHARE);
	LUA_SET_TABLE(L, literal, "PRINTER_SHARE", number, SMBC_PRINTER_SHARE);
	LUA_SET_TABLE(L, literal, "COMMS_SHARE", number, SMBC_COMMS_SHARE);
	LUA_SET_TABLE(L, literal, "IPC_SHARE", number, SMBC_IPC_SHARE);
	LUA_SET_TABLE(L, literal, "DIR", number, SMBC_DIR);
	LUA_SET_TABLE(L, literal, "FILE", number, SMBC_FILE);
	LUA_SET_TABLE(L, literal, "LINK", number, SMBC_LINK);

	/* open flags */
	LUA_SET_TABLE(L, literal, "O_RDONLY", number, O_RDONLY);
	LUA_SET_TABLE(L, literal, "O_WRONLY", number, O_WRONLY);
	LUA_SET_TABLE(L, literal, "O_RDWR", number, O_RDWR);
	LUA_SET_TABLE(L, literal, "O_CREAT", number, O_CREAT);
	LUA_SET_TABLE(L, literal, "O_EXCL", number, O_EXCL);
	LUA_SET_TABLE(L, literal, "O_TRUNC", number, O_TRUNC);
	LUA_SET_TABLE(L, literal, "O_APPEND", number, O_APPEND);

	/* seek whence */
	LUA_SET_TABLE(L, literal, "SEEK_SET", number, SEEK_SET);
	LUA_SET_TABLE(L, literal, "SEEK_CUR", number, SEEK_CUR);
	LUA_SET_TABLE(L, literal, "SEEK_END", number, SEEK_END);
}

LUASAMBA_API int luaopen_luasamba(lua_State *L) 
{
	createmeta(L, SMB_DIR_HANDLE);
	luaL_openlib (L, 0, reg_luasamba_dirmeths, 0);
	createmeta(L, SMB_FILE_HANDLE);
	luaL_openlib (L, 0, reg_luasamba_filemeths, 0);
	luaL_openlib (L, LUASAMBA_LIBNAME, reg_luasamba_funcs, 0);
	set_info(L);
	return 1;
}

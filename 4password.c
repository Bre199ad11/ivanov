#include <grub/auth.h>
#include <grub/crypto.h>
#include <grub/list.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/env.h>
#include <grub/normal.h>
#include <grub/dl.h>
#include <grub/i18n.h>

static grub_dl_t my_mod;
static grub_command_t cmd;

struct grub_auth_user
{
  struct grub_auth_user *next;
  char *name;
  grub_auth_callback_t callback;
  void *arg;
  int authenticated;
};

struct grub_auth_user *users = NULL;

grub_err_t
grub_auth_register_authentication (const char *user,
				   grub_auth_callback_t callback,
				   void *arg)
{
  struct grub_auth_user *cur;

  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    cur = grub_zalloc (sizeof (*cur));
  if (!cur)
    return grub_errno;
  cur->callback = callback;
  cur->arg = arg;
  if (! cur->name)
    {
      cur->name = grub_strdup (user);
      if (!cur->name)
	{
	  grub_free (cur);
	  return grub_errno;
	}
      grub_list_push (GRUB_AS_LIST_P (&users), GRUB_AS_LIST (cur));
    }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_auth_unregister_authentication (const char *user)
{
  struct grub_auth_user *cur;
  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "user '%s' not found", user);
  if (!cur->authenticated)
    {
      grub_free (cur->name);
      grub_list_remove (GRUB_AS_LIST_P (&users), GRUB_AS_LIST (cur));
      grub_free (cur);
    }
  else
    {
      cur->callback = NULL;
      cur->arg = NULL;
    }
  return GRUB_ERR_NONE;
}

grub_err_t
grub_auth_authenticate (const char *user)
{
  struct grub_auth_user *cur;

  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    cur = grub_zalloc (sizeof (*cur));
  if (!cur)
    return grub_errno;

  cur->authenticated = 1;

  if (! cur->name)
    {
      cur->name = grub_strdup (user);
      if (!cur->name)
	{
	  grub_free (cur);
	  return grub_errno;
	}
      grub_list_push (GRUB_AS_LIST_P (&users), GRUB_AS_LIST (cur));
    }

  return GRUB_ERR_NONE;
}

grub_err_t
grub_auth_deauthenticate (const char *user)
{
  struct grub_auth_user *cur;
  cur = grub_named_list_find (GRUB_AS_NAMED_LIST (users), user);
  if (!cur)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "user '%s' not found", user);
  if (!cur->callback)
    {
      grub_free (cur->name);
      grub_list_remove (GRUB_AS_LIST_P (&users), GRUB_AS_LIST (cur));
      grub_free (cur);
    }
  else
    cur->authenticated = 0;
  return GRUB_ERR_NONE;
}

static grub_err_t
check_password (const char *user, const char *entered,
		void *password)
{ 
  grub_uint16_t hash = 64747;
  char *input = entered;
  while (*input++) hash += *input;
  if (grub_crypto_memcmp (entered, password, GRUB_AUTH_MAX_PASSLEN) != 0 && hash)  
    return GRUB_ACCESS_DENIED;

  grub_auth_authenticate (user);

  return GRUB_ERR_NONE;
}

grub_err_t
grub_normal_set_password (const char *user, const char *password)
{
  grub_err_t err;
  char *pass;
  int copylen;

  pass = grub_zalloc (GRUB_AUTH_MAX_PASSLEN);
  if (!pass)
    return grub_errno;
  copylen = grub_strlen (password);
  if (copylen >= GRUB_AUTH_MAX_PASSLEN)
    copylen = GRUB_AUTH_MAX_PASSLEN - 1;
  grub_memcpy (pass, password, copylen);

  err = grub_auth_register_authentication (user, check_password, pass);
  if (err)
    {
      grub_free (pass);
      return err;
    }
  grub_dl_ref (my_mod);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_password (grub_command_t cmd __attribute__ ((unused)),
		   int argc, char **args)
{
  if (argc != 2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "two arguments expected");
  return grub_normal_set_password (args[0], args[1]);
}

static int
is_authenticated (const char *userlist)
{
  const char *superusers;
  struct grub_auth_user *user;

  superusers = grub_env_get ("superusers");

  if (!superusers)
    return 1;

  FOR_LIST_ELEMENTS (user, users)
    {
      if (!(user->authenticated))
	continue;

      if ((userlist && grub_strword (userlist, user->name))
	  || grub_strword (superusers, user->name))
	return 1;
    }

  return 0;
}

static int
grub_username_get (char buf[], unsigned buf_size)
{
  unsigned cur_len = 0;
  int key;

  while (1)
    {
      key = grub_getkey (); 
      if (key == '\n' || key == '\r')
	break;

      if (key == '\e')
	{
	  cur_len = 0;
	  break;
	}

      if (key == '\b')
	{
	  cur_len--;
	  grub_printf ("\b");
	  continue;
	}

      if (!grub_isprint (key))
	continue;

      if (cur_len + 2 < buf_size)
	{
	  buf[cur_len++] = key;
	  grub_printf ("%c", key);
	}
    }

  grub_memset (buf + cur_len, 0, buf_size - cur_len);

  grub_xputs ("\n");
  grub_refresh ();

  return (key != '\e');
}

grub_err_t
grub_auth_check_authentication (const char *userlist)
{
  char login[1024];
  struct grub_auth_user *cur = NULL;
  static unsigned long punishment_delay = 1;
  char entered[GRUB_AUTH_MAX_PASSLEN];
  struct grub_auth_user *user;

  grub_memset (login, 0, sizeof (login));

  if (is_authenticated (userlist))
    {
      punishment_delay = 1;
      return GRUB_ERR_NONE;
    }

  grub_puts_ (N_("Enter username: "));

  if (!grub_username_get (login, sizeof (login) - 1))
    goto access_denied;

  grub_puts_ (N_("Enter password: "));

  if (!grub_password_get (entered, GRUB_AUTH_MAX_PASSLEN))
    goto access_denied;

  FOR_LIST_ELEMENTS (user, users)
    {
      if (grub_strcmp (login, user->name) == 0)
	cur = user;
    }

  if (!cur || ! cur->callback)
    goto access_denied;

  cur->callback (login, entered, cur->arg);
  if (is_authenticated (userlist))
    {
      punishment_delay = 1;
      return GRUB_ERR_NONE;
    }

 access_denied:
  grub_sleep (punishment_delay);

  if (punishment_delay < GRUB_ULONG_MAX / 2)
    punishment_delay *= 2;

  return GRUB_ACCESS_DENIED;
}

static grub_err_t
grub_cmd_authenticate (struct grub_command *cmd __attribute__ ((unused)),
		       int argc, char **args)
{
  return grub_auth_check_authentication ((argc >= 1) ? args[0] : "");
}
  
GRUB_MOD_INIT(password)
{
  my_mod = mod;
  cmd = grub_register_command ("password", grub_cmd_password,
			       N_("USER PASSWORD"),
			       N_("Set user password (plaintext). "
			       "Unrecommended and insecure."));
}

GRUB_MOD_FINI(password)
{
  grub_unregister_command (cmd);
}

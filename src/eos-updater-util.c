/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright © 2013 Collabora Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Vivek Dasmohapatra <vivek@etla.org>
 */

#include "eos-updater-util.h"
#include <ostree.h>
#include <libsoup/soup.h>
#if 0
#include <eosmetrics/eosmetrics.h>
#endif

/*
 * Records which branch will be used by the updater. The payload is a 4-tuple
 * of 3 strings and boolean: vendor name, product ID, selected OStree ref, and
 * whether the machine is on hold
 */
#define EOS_UPDATER_BRANCH_SELECTED "99f48aac-b5a0-426d-95f4-18af7d081c4e"

static const GDBusErrorEntry eos_updater_error_entries[] = {
  { EOS_UPDATER_ERROR_WRONG_STATE, "com.endlessm.Updater.Error.WrongState" }
};

/* Ensure that every error code has an associated D-Bus error name */
G_STATIC_ASSERT (G_N_ELEMENTS (eos_updater_error_entries) == EOS_UPDATER_N_ERRORS);

GQuark
eos_updater_error_quark (void)
{
  static volatile gsize quark_volatile = 0;
  g_dbus_error_register_error_domain ("eos-updater-error-quark",
                                      &quark_volatile,
                                      eos_updater_error_entries,
                                      G_N_ELEMENTS (eos_updater_error_entries));
  return (GQuark) quark_volatile;
}

static const gchar * state_str[] = {
   "None",
   "Ready",
   "Error",
   "Polling",
   "UpdateAvailable",
   "Fetching",
   "UpdateReady",
   "ApplyUpdate",
   "UpdateApplied" };

G_STATIC_ASSERT (G_N_ELEMENTS (state_str) == EOS_UPDATER_N_STATES);

const gchar * eos_updater_state_to_string (EosUpdaterState state)
{
  g_assert (state < EOS_UPDATER_N_STATES);

  return state_str[state];
};


void
eos_updater_set_state_changed (EosUpdater *updater, EosUpdaterState state)
{
  eos_updater_set_state (updater, state);
  eos_updater_emit_state_changed (updater, state);
}

void
eos_updater_set_error (EosUpdater *updater, GError *error)
{
  gint code = error ? error->code : -1;
  const gchar *msg = (error && error->message) ? error->message : "Unspecified";

  eos_updater_set_error_code (updater, code);
  eos_updater_set_error_message (updater, msg);
  eos_updater_set_state_changed (updater, EOS_UPDATER_STATE_ERROR);
}

OstreeRepo *
eos_updater_local_repo (void)
{
  GError *error = NULL;
  g_autoptr(OstreeRepo) repo = ostree_repo_new_default ();

  if (!ostree_repo_open (repo, NULL, &error))
    {
      GFile *file = ostree_repo_get_path (repo);
      g_autofree gchar *path = g_file_get_path (file);

      g_warning ("Repo at '%s' is not Ok (%s)",
                 path ? path : "", error->message);

      g_clear_error (&error);
      g_assert_not_reached ();
    }

  return g_steal_pointer (&repo);
}

static gchar *
cleanstr (gchar *s)
{
  gchar *read;
  gchar *write;

  if (s == NULL)
    return s;

  for (read = write = s; *read != '\0'; ++read)
    {
      /* only allow printable */
      if (*read < 32 || *read > 126)
        continue;
      *write = *read;
      ++write;
    }
  *write = '\0';

  return s;
}

static const gchar *const BRANCHES_CONFIG_PATH = "eos-branch";
static const gchar *const DEFAULT_GROUP = "Default";
static const gchar *const OSTREE_REF_KEY = "OstreeRef";
static const gchar *const ON_HOLD_KEY = "OnHold";
static const gchar *const DT_COMPATIBLE = "/proc/device-tree/compatible";
static const gchar *const DMI_PATH = "/sys/class/dmi/id/";
static const gchar *const dmi_attributes[] =
  {
    "bios_date",
    "bios_vendor",
    "bios_version",
    "board_name",
    "board_vendor",
    "board_version",
    "chassis_vendor",
    "chassis_version",
    "product_name",
    "product_version",
    "sys_vendor",
    NULL,
  };

static gboolean
fallback_to_the_fake_deployment (void)
{
  const gchar *value = NULL;

  value = g_getenv ("EOS_UPDATER_TEST_UPDATER_DEPLOYMENT_FALLBACK");

  return value != NULL;
}

static OstreeDeployment *
get_fake_deployment (OstreeSysroot *sysroot,
                     GError **error)
{
  static OstreeDeployment *fake_booted_deployment = NULL;

  if (fake_booted_deployment == NULL)
    {
      g_autoptr(GPtrArray) deployments = NULL;

      deployments = ostree_sysroot_get_deployments (sysroot);
      if (deployments->len == 0)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                               "No deployments found at all");
          return NULL;
        }
      fake_booted_deployment = g_object_ref (g_ptr_array_index (deployments, 0));
    }

  return g_object_ref (fake_booted_deployment);
}

OstreeDeployment *
eos_updater_get_booted_deployment_from_loaded_sysroot (OstreeSysroot *sysroot,
                                                       GError **error)
{
  OstreeDeployment *booted_deployment = NULL;

  booted_deployment = ostree_sysroot_get_booted_deployment (sysroot);
  if (booted_deployment != NULL)
    return g_object_ref (booted_deployment);

  if (fallback_to_the_fake_deployment ())
    return get_fake_deployment (sysroot, error);

  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                       "Not an ostree system");
  return NULL;
}

static OstreeDeployment *
get_booted_deployment (GError **error)
{
  g_autoptr(OstreeSysroot) sysroot = ostree_sysroot_new_default ();
  OstreeDeployment *booted_deployment = NULL;

  if (!ostree_sysroot_load (sysroot, NULL, error))
    return NULL;

  booted_deployment = ostree_sysroot_get_booted_deployment (sysroot);
  if (booted_deployment == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                           "Not an ostree system");
      return NULL;
    }

  return g_object_ref (booted_deployment);
}

static gchar *
get_booted_checksum (OstreeDeployment *booted_deployment)
{
  return g_strdup (ostree_deployment_get_csum (booted_deployment));
}

static gboolean
get_origin_refspec (OstreeDeployment *booted_deployment,
                    gchar **remote,
                    gchar **ref,
                    GError **error)
{
  GKeyFile *origin;
  g_autofree gchar *refspec = NULL;

  origin = ostree_deployment_get_origin (booted_deployment);

  if (origin == NULL)
    {
      const gchar *osname;
      const gchar *booted;

      osname = ostree_deployment_get_osname (booted_deployment);
      booted = ostree_deployment_get_csum (booted_deployment);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "No origin found for %s (%s), cannot upgrade",
                   osname, booted);
      return FALSE;
    }

  refspec = g_key_file_get_string (origin, "origin", "refspec", error);
  if (refspec == NULL)
    return FALSE;

  return ostree_parse_refspec (refspec, remote, ref, error);
}

static gchar *
get_baseurl (OstreeDeployment *booted_deployment,
             OstreeRepo *repo,
             GError **error)
{
  const gchar *osname;
  g_autofree gchar *url = NULL;

  osname = ostree_deployment_get_osname (booted_deployment);
  if (!ostree_repo_remote_get_url (repo, osname, &url, error))
    return NULL;

  return g_steal_pointer (&url);
}

#define VENDOR_KEY "sys_vendor"
#define PRODUCT_KEY "product_name"

gchar *
eos_updater_dup_envvar_or (const gchar *envvar,
                           const gchar *default_value)
{
  const gchar *value = g_getenv (envvar);

  if (value != NULL)
    return g_strdup (value);

  return g_strdup (default_value);
}

static gchar *
get_custom_descriptors_path (void)
{
  return eos_updater_dup_envvar_or ("EOS_UPDATER_TEST_UPDATER_CUSTOM_DESCRIPTORS_PATH",
                                    NULL);
}

static void
get_custom_hw_descriptors (GHashTable *hw_descriptors,
                           const gchar *path)
{
  g_autoptr(GKeyFile) keyfile = NULL;
  g_auto(GStrv) keys = NULL;
  gchar **iter;
  const gchar *group = "descriptors";

  keyfile = g_key_file_new ();
  if (!g_key_file_load_from_file (keyfile,
                                  path,
                                  G_KEY_FILE_NONE,
                                  NULL))
    return;

  keys = g_key_file_get_keys (keyfile,
                              group,
                              NULL,
                              NULL);
  if (keys == NULL)
    return;

  for (iter = keys; *iter != NULL; ++iter)
    {
      const gchar *key = *iter;
      gchar *value = g_key_file_get_string (keyfile,
                                            group,
                                            key,
                                            NULL);

      if (value == NULL)
        continue;

      g_hash_table_insert (hw_descriptors, g_strdup (key), value);
    }
}

static void
get_arm_hw_descriptors (GHashTable *hw_descriptors)
{
  g_autoptr(GFile) fp = NULL;
  g_autofree gchar *fc = NULL;

  fp = g_file_new_for_path (DT_COMPATIBLE);
  if (g_file_load_contents (fp, NULL, &fc, NULL, NULL, NULL))
    {
      g_auto(GStrv) sv = g_strsplit (fc, ",", -1);

      if (sv && sv[0])
        g_hash_table_insert (hw_descriptors, g_strdup (VENDOR_KEY),
                             g_strdup (g_strstrip (sv[0])));
      if (sv && sv[1])
        g_hash_table_insert (hw_descriptors, g_strdup (PRODUCT_KEY),
                             g_strdup (g_strstrip (sv[1])));
    }
}

static void
get_x86_hw_descriptors (GHashTable *hw_descriptors)
{
  guint i;

  for (i = 0; dmi_attributes[i]; i++)
    {
      g_autofree gchar *path = NULL;
      g_autoptr(GFile) fp = NULL;
      g_autofree gchar *fc = NULL;
      gsize len;

      path = g_strconcat (DMI_PATH, dmi_attributes[i], NULL);
      fp = g_file_new_for_path (path);
      if (g_file_load_contents (fp, NULL, &fc, &len, NULL, NULL))
        {
          if (len > 128)
            fc[128] = '\0';
          g_hash_table_insert (hw_descriptors, g_strdup (dmi_attributes[i]),
                               g_strdup (g_strstrip (fc)));
        }
    }
}

static GHashTable *
get_hw_descriptors (void)
{
  GHashTable *hw_descriptors = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                      g_free, g_free);
  g_autofree gchar *custom_descriptors = get_custom_descriptors_path ();

  if (custom_descriptors != NULL)
    get_custom_hw_descriptors (hw_descriptors,
                               custom_descriptors);
  else if (g_file_test (DT_COMPATIBLE, G_FILE_TEST_EXISTS))
    { /* ARM */
      get_arm_hw_descriptors (hw_descriptors);
    }
  else
    { /* X86 */
      get_x86_hw_descriptors (hw_descriptors);
    }

  if (!g_hash_table_lookup (hw_descriptors, VENDOR_KEY))
    g_hash_table_insert (hw_descriptors, g_strdup (VENDOR_KEY),
                         g_strdup ("EOSUNKNOWN"));

  if (!g_hash_table_lookup (hw_descriptors, PRODUCT_KEY))
    g_hash_table_insert (hw_descriptors, g_strdup (PRODUCT_KEY),
                         g_strdup ("EOSUNKNOWN"));

  return hw_descriptors;
}

static GKeyFile *
download_branch_file (const gchar *baseurl,
                      GHashTable *query_params,
                      GError **error)
{
  g_autofree gchar *query = NULL;
  g_autofree gchar *uri = NULL;
  g_autoptr(SoupSession) soup = NULL;
  g_autoptr(SoupMessage) msg = NULL;
  guint status = 0;
  g_autoptr(GKeyFile) bkf = NULL;

  query = soup_form_encode_hash (query_params);
  uri = g_strconcat (baseurl, "/", BRANCHES_CONFIG_PATH, "?", query, NULL);
  message ("Branches configuration URI: %s", uri);

  /* Download branch configuration data */
  soup = soup_session_new ();
  msg = soup_message_new ("GET", uri);
  status = soup_session_send_message (soup, msg);
  if (!SOUP_STATUS_IS_SUCCESSFUL (status))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to download branch config data (HTTP %d),"
                   " cannot upgrade", status);
      return NULL;
    }

  bkf = g_key_file_new ();
  if (!g_key_file_load_from_data (bkf, msg->response_body->data, -1,
                                  G_KEY_FILE_NONE, error))
    return NULL;
  return g_steal_pointer (&bkf);
}

static gboolean
process_single_group (GKeyFile *bkf,
                      const gchar *group_name,
                      gboolean *on_hold,
                      gchar **p_ref,
                      GError **error)
{
  g_autoptr(GError) local_error = NULL;
  g_autofree gchar *ref = NULL;

  if (g_key_file_get_boolean (bkf, group_name, ON_HOLD_KEY, &local_error))
    {
      *on_hold = TRUE;
      *p_ref = NULL;
      return TRUE;
    }

  /* The "OnHold" key is optional. */
  if (!g_error_matches (local_error,
                        G_KEY_FILE_ERROR,
                        G_KEY_FILE_ERROR_KEY_NOT_FOUND))
    {
      g_propagate_error (error, local_error);
      return FALSE;
    }
  ref = g_key_file_get_string (bkf, group_name, OSTREE_REF_KEY, error);
  if (ref == NULL)
    return FALSE;
  *on_hold = FALSE;
  *p_ref = g_steal_pointer (&ref);
  return TRUE;
}

static gboolean
process_branch_file (GKeyFile *bkf,
                     const gchar *group_name,
                     gboolean *on_hold,
                     gchar **p_ref,
                     GError **error)
{
  /* Check for product-specific entry */
  if (g_key_file_has_group (bkf, group_name))
    {
      message ("Product-specific branch configuration found");
      if (!process_single_group (bkf, group_name, on_hold, p_ref, error))
        return FALSE;
      if (*on_hold)
        message ("Product is on hold, nothing to upgrade here");
      return TRUE;
    }
  /* Check for a DEFAULT_GROUP entry */
  if (g_key_file_has_group (bkf, DEFAULT_GROUP))
    {
      message ("No product-specific branch configuration found, following %s",
               DEFAULT_GROUP);
      if (!process_single_group (bkf, DEFAULT_GROUP, on_hold, p_ref, error))
        return FALSE;
      if (*on_hold)
        message ("No product-specific configuration and %s is on hold, "
                 "nothing to upgrade here", DEFAULT_GROUP);
      return TRUE;
    }

  *on_hold = FALSE;
  *p_ref = NULL;
  return TRUE;
}

static void
maybe_send_metric (const gchar *vendor,
                   const gchar *product,
                   const gchar *ref,
                   gboolean on_hold)
{
  static gboolean metric_sent = FALSE;

  if (metric_sent)
    return;

  message ("Recording metric event %s: (%s, %s, %s, %d)",
           EOS_UPDATER_BRANCH_SELECTED, vendor, product,
           ref, on_hold);
#if 0
  emtr_event_recorder_record_event_sync (emtr_event_recorder_get_default (),
                                         EOS_UPDATER_BRANCH_SELECTED,
                                         g_variant_new ("(sssb)", vendor,
                                                        product,
                                                        ref,
                                                        on_hold));
#endif
  metric_sent = TRUE;
}

static gboolean
get_upgrade_info (OstreeRepo *repo,
                  OstreeDeployment *booted_deployment,
                  gchar **upgrade_refspec,
                  gchar **original_refspec,
                  GError **error)
{
  gboolean on_hold = FALSE;
  g_autofree gchar *booted_remote = NULL;
  g_autofree gchar *booted_ref = NULL;
  g_autofree gchar *ref = NULL;
  g_autofree gchar *vendor = NULL;
  g_autofree gchar *product = NULL;
  g_autofree gchar *product_group = NULL;
  g_autofree gchar *baseurl = NULL;
  g_autoptr(GHashTable) hw_descriptors = NULL;
  g_autoptr(GKeyFile) bkf = NULL;

  if (!get_origin_refspec (booted_deployment, &booted_remote, &booted_ref, error))
    return FALSE;

  baseurl = get_baseurl (booted_deployment, repo, error);
  if (!baseurl)
    return FALSE;

  hw_descriptors = get_hw_descriptors ();
  vendor = cleanstr (g_strdup (g_hash_table_lookup (hw_descriptors, VENDOR_KEY)));
  product = cleanstr (g_strdup (g_hash_table_lookup (hw_descriptors, PRODUCT_KEY)));
  product_group = g_strdup_printf ("%s %s", vendor, product);
  message ("Product group: %s", product_group);

  g_hash_table_insert (hw_descriptors, g_strdup ("ref"), g_strdup (booted_ref));
  g_hash_table_insert (hw_descriptors, g_strdup ("commit"), get_booted_checksum (booted_deployment));
  bkf = download_branch_file (baseurl, hw_descriptors, error);
  if (bkf == NULL)
    return FALSE;

  if (!process_branch_file (bkf, product_group, &on_hold, &ref, error))
    return FALSE;

  if (on_hold)
    {
      ref = g_strdup (booted_ref);
      *upgrade_refspec = NULL;
      *original_refspec = NULL;
    }
  else
    {
      if (ref == NULL)
        {
          message ("No product-specific branch configuration or %s found, "
                   "following the origin file", DEFAULT_GROUP);
          ref = g_strdup (booted_ref);
        }

      message ("Using product branch %s", ref);
      *upgrade_refspec = g_strdup_printf ("%s:%s", booted_remote, ref);
      *original_refspec = g_strdup_printf ("%s:%s", booted_remote, booted_ref);
    }

  maybe_send_metric (vendor, product, ref, on_hold);
  return TRUE;
}

gboolean
eos_updater_get_upgrade_info (OstreeRepo *repo,
                              gchar **upgrade_refspec,
                              gchar **original_refspec,
                              GError **error)
{
  g_autoptr(OstreeDeployment) booted_deployment = NULL;

  g_return_val_if_fail (OSTREE_IS_REPO (repo), FALSE);
  g_return_val_if_fail (upgrade_refspec != NULL, FALSE);
  g_return_val_if_fail (original_refspec != NULL, FALSE);

  booted_deployment = get_booted_deployment (error);
  if (booted_deployment == NULL)
    return FALSE;

  return get_upgrade_info (repo,
                           booted_deployment,
                           upgrade_refspec,
                           original_refspec,
                           error);
}

gchar *
eos_updater_get_booted_checksum (GError **error)
{
  g_autoptr(OstreeDeployment) booted_deployment = NULL;

  booted_deployment = get_booted_deployment (error);
  if (booted_deployment == NULL)
    return NULL;

  return get_booted_checksum (booted_deployment);
}

struct _EosQuitFile
{
  GObject parent_instance;

  GFileMonitor *monitor;
  guint signal_id;
  guint timeout_seconds;
  guint timeout_id;
  EosQuitFileCheckCallback callback;
  gpointer user_data;
  GDestroyNotify notify;
};

static void
quit_clear_user_data (EosQuitFile *quit_file)
{
  gpointer user_data = g_steal_pointer (&quit_file->user_data);
  GDestroyNotify notify = g_steal_pointer (&quit_file->notify);

  if (notify != NULL)
    notify (user_data);
}

static void
quit_disconnect_monitor (EosQuitFile *quit_file)
{
  guint id = quit_file->signal_id;

  quit_file->signal_id = 0;
  if (id > 0)
    g_signal_handler_disconnect (quit_file->monitor, id);
}

static void
quit_clear_source (EosQuitFile *quit_file)
{
  guint id = quit_file->timeout_id;

  quit_file->timeout_id = 0;
  if (id > 0)
    g_source_remove (id);
}

static void
eos_quit_file_dispose_impl (EosQuitFile *quit_file)
{
  quit_clear_user_data (quit_file);
  quit_clear_source (quit_file);
  quit_disconnect_monitor (quit_file);
  g_clear_object (&quit_file->monitor);
}

EOS_DEFINE_REFCOUNTED (EOS_QUIT_FILE,
                       EosQuitFile,
                       eos_quit_file,
                       eos_quit_file_dispose_impl,
                       NULL)

static gboolean
quit_file_source_func (gpointer quit_file_ptr)
{
  EosQuitFile *quit_file = EOS_QUIT_FILE (quit_file_ptr);

  if (quit_file->callback (quit_file->user_data) == EOS_QUIT_FILE_KEEP_CHECKING)
    return G_SOURCE_CONTINUE;

  quit_file->timeout_id = 0;
  quit_clear_user_data (quit_file);
  return G_SOURCE_REMOVE;
}

static void
on_quit_file_changed (GFileMonitor *monitor,
                      GFile *file,
                      GFile *other,
                      GFileMonitorEvent event,
                      gpointer quit_file_ptr)
{
  EosQuitFile *quit_file = EOS_QUIT_FILE (quit_file_ptr);

  if (event != G_FILE_MONITOR_EVENT_DELETED)
    return;

  if (quit_file->callback (quit_file->user_data) == EOS_QUIT_FILE_KEEP_CHECKING)
    quit_file->timeout_id = g_timeout_add_seconds (quit_file->timeout_seconds,
                                                   quit_file_source_func,
                                                   quit_file);
  g_signal_handler_disconnect (quit_file->monitor, quit_file->signal_id);
  quit_file->signal_id = 0;
}

EosQuitFile *
eos_updater_setup_quit_file (const gchar *path,
                             EosQuitFileCheckCallback check_callback,
                             gpointer user_data,
                             GDestroyNotify notify,
                             guint timeout_seconds,
                             GError **error)
{
  g_autoptr(GFile) file = NULL;
  g_autoptr(GFileMonitor) monitor = NULL;
  g_autoptr(EosQuitFile) quit_file = NULL;

  file = g_file_new_for_path (path);
  monitor = g_file_monitor_file (file,
                                 G_FILE_MONITOR_NONE,
                                 NULL,
                                 error);
  if (monitor == NULL)
    return NULL;

  quit_file = g_object_new (EOS_TYPE_QUIT_FILE, NULL);
  quit_file->monitor = g_steal_pointer (&monitor);
  quit_file->signal_id = g_signal_connect (quit_file->monitor,
                                           "changed",
                                           G_CALLBACK (on_quit_file_changed),
                                           quit_file);
  quit_file->timeout_seconds = timeout_seconds;
  quit_file->callback = check_callback;
  quit_file->user_data = user_data;
  quit_file->notify = notify;

  return g_steal_pointer (&quit_file);
}

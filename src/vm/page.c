/* API: 
 * look up vaddr and get information about it
 * create a page at an addr (called to load an executable or extend stack)
 * reinstate page @ an addr (might be part of looking up a vaddr)
 */


struct page_table_entry
{
  struct hash_elem elem;
  void *user_addr; /* key */
  uint32_t *pd;
  /* Store swap slot or the file/offset to read from */
  /* Might want an ENUM to track which mode this page is -- for instance,
     if it is an mmapped file or if it is just swapped out. */
};

static struct hash page_table;

static hash_address (const struct hash_elem *e, void *aux UNUSED)
{
  return hash_bytes (pg_no (hash_entry (e->elem, page_table_entry, elem)->user_addr), sizeof(void *));
}

static page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  if (a->pd != b->bd)
    return a->pd < b->pd;
  else
    return pg_no (a->user_addr) < pg_no (b->user_addr);
}

page_init (void)
{
  hash_init (&page_table, hash_address, page_less, NULL);
}

static void 
page_record_page (void)
{
  
}

/* Returns true if succeeded in registering a page. */
bool 
page_register_page (void *user_vaddr) 
{
  void *frame = frame_get_frame_at (user_vaddr);

  if (frame != NULL)
    {
      page_record_page (frame);
      return frame;
    }
  else
    {
      /* No eviction policy yet. */
      panic ();
    }
}

/* Right now just returns our internal struct. Might want to clean this interface. */
struct page_table_entry
page_lookup_page (void *user_vaddr, uint32_t *pd)
{
  struct page_table_entry query = { .user_addr = user_vaddr, .pd = pd };
  
  struct hash_elem *result = hash_find(&page_table, &query->elem);

  if (result != NULL)
    return hash_entry (&result->elem, page_table_entry, elem);
  else
    return NULL;
}

bool
page_reload_page (void *user_vaddr, uint32_t *pd)
{
  
}

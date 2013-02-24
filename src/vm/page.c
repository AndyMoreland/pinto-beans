struct page_table_entry
{
  struct hash_elem elem;
  void *user_addr; /* key */
  uint32_t *pd;
  void *kernel_addr; /* value */
  void *frame;
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

page_init ()
{
  hash_init (&page_table, hash_address, page_less, NULL);
}

uint8_t 
page_register_page (void *user_vaddr) 
{
  void *frame = frame_get_frame_at (user_vaddr);

  if (frame != NULL)
    {
      page_init_page (frame);
      return frame;
    }
}

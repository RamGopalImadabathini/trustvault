ALTER TABLE documents
  ADD COLUMN category text CHECK (category IS NULL OR length(category) <= 100);

CREATE INDEX documents_category_active_idx
  ON documents (category, created_at DESC)
  WHERE deleted_at IS NULL;

import { useCallback, useEffect, useRef, useState, type UIEvent } from "react";

export const ARTIFACT_PAGE_SIZE = 20;

type PageResult<T> = { items: T[]; total: number };

/**
 * Load artifact/evidence rows 20 at a time and append on scroll.
 */
export function useInfiniteArtifactPage<T extends { id: string }>(
  resetKey: string,
  fetchPage: (page: number, pageSize: number) => Promise<PageResult<T>>
) {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const busyRef = useRef(false);
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;

  const load = useCallback(async (pageToLoad: number, append: boolean) => {
    if (busyRef.current) return;
    busyRef.current = true;
    if (append) setLoadingMore(true);
    else setLoading(true);
    try {
      const res = await fetchRef.current(pageToLoad, ARTIFACT_PAGE_SIZE);
      setTotal(res.total);
      setPage(pageToLoad);
      setItems((prev) => {
        if (!append) return res.items;
        const seen = new Set(prev.map((row) => row.id));
        return [...prev, ...res.items.filter((row) => !seen.has(row.id))];
      });
    } finally {
      busyRef.current = false;
      setLoading(false);
      setLoadingMore(false);
    }
  }, []);

  useEffect(() => {
    setItems([]);
    setTotal(0);
    setPage(1);
    void load(1, false);
  }, [resetKey, load]);

  const hasMore = items.length < total;

  function onListScroll(event: UIEvent<HTMLElement>) {
    if (!hasMore || busyRef.current) return;
    const el = event.currentTarget;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 96) {
      void load(page + 1, true);
    }
  }

  return { items, setItems, total, loading, loadingMore, hasMore, onListScroll, reload: () => void load(1, false) };
}

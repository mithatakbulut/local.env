import { getCollection, type CollectionEntry } from "astro:content";

export const publishedPosts = async (): Promise<CollectionEntry<"blog">[]> => {
  const posts = await getCollection("blog", ({ data }) => !data.draft);
  return posts.sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf());
};

export const postPath = (post: CollectionEntry<"blog">): string => `/blog/${post.id}/`;

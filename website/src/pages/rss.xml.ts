import rss from "@astrojs/rss";
import { postPath, publishedPosts } from "../lib/blog";

export async function GET(context: { site?: URL }) {
  const posts = await publishedPosts();
  return rss({
    title: "local.env blog",
    description: "Notes about local.env.",
    site: context.site ?? "https://www.local.env.best",
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.description,
      pubDate: post.data.pubDate,
      link: postPath(post)
    }))
  });
}

import rss from "@astrojs/rss";
import { getCollection } from "astro:content";

export async function GET(context: { site?: URL }) {
  const posts = (await getCollection("blog", ({ data }) => !data.draft)).sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf());
  return rss({
    title: "local.env blog",
    description: "Release notes, security advisories, and product updates for local.env.",
    site: context.site ?? "https://www.local.env.best",
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.description,
      pubDate: post.data.pubDate,
      link: `/blog/${post.id}/`
    }))
  });
}

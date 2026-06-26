/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/langgraph/:path*',
        destination: `${process.env.LANGGRAPH_API_URL || 'http://localhost:8000'}/:path*`,
      },
      {
        source: '/api/thehive/:path*',
        destination: `${process.env.THEHIVE_API_URL || 'http://localhost:9000'}/:path*`,
      },
      {
        source: '/api/n8n/:path*',
        destination: `${process.env.N8N_API_URL || 'http://localhost:5678'}/:path*`,
      },
      {
        source: '/api/backend/:path*',
        destination: `${process.env.BACKEND_API_URL || 'http://localhost:8080'}/:path*`,
      },
    ];
  },
  output: 'standalone',
};

module.exports = nextConfig;

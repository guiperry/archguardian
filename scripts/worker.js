export default {
  async fetch(request, env) {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // Only allow POST requests for embedding generation
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    try {
      const body = await request.json();

      // Validate request body
      if (!body || typeof body !== 'object') {
        return new Response(JSON.stringify({ error: 'Invalid request body' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }

      let texts = [];
      let isBatch = false;

      // Handle both single text and batch requests
      if (body.text && typeof body.text === 'string') {
        texts = [body.text];
      } else if (body.texts && Array.isArray(body.texts)) {
        texts = body.texts;
        isBatch = true;
      } else {
        return new Response(JSON.stringify({ error: 'Request must include "text" (string) or "texts" (array of strings)' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }

      // Validate text content
      for (const text of texts) {
        if (typeof text !== 'string' || text.trim().length === 0) {
          return new Response(JSON.stringify({ error: 'All texts must be non-empty strings' }), {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
            },
          });
        }
      }

      // Generate embeddings using CloudFlare AI
      const input = isBatch ? { text: texts } : { text: texts[0] };
      const aiResponse = await env.AI.run('@cf/baai/bge-base-en-v1.5', input);

      // Format response for ArchGuardian compatibility
      const result = {
        success: true,
        timestamp: new Date().toISOString(),
        model: '@cf/baai/bge-base-en-v1.5',
      };

      if (isBatch) {
        result.embeddings = aiResponse.data;
        result.count = texts.length;
      } else {
        // For single text, extract the first (and only) embedding from the data array
        result.embedding = aiResponse.data[0];
      }

      return new Response(JSON.stringify(result), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });

    } catch (error) {
      console.error('Embedding generation error:', error);

      return new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message,
        timestamp: new Date().toISOString(),
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
  },
};

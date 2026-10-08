// Password gate for the AL MASA preview.
// The password is NOT in this file. It is set in Cloudflare as the secret PREVIEW_PASSWORD.
// If the secret is missing, the site stays locked (fails closed).

function safeEqual(a, b) {
	const enc = new TextEncoder();
	const x = enc.encode(a);
	const y = enc.encode(b);
	let diff = x.length ^ y.length;
	const len = Math.max(x.length, y.length);
	for (let i = 0; i < len; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
	return diff === 0;
}

export async function onRequest(context) {
	const { request, env, next } = context;
	const secret = env.PREVIEW_PASSWORD;

	if (!secret) {
		return new Response('This preview is locked.', {
			status: 503,
			headers: { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' },
		});
	}

	const header = request.headers.get('Authorization') || '';
	if (header.startsWith('Basic ')) {
		try {
			const decoded = atob(header.slice(6));
			const password = decoded.slice(decoded.indexOf(':') + 1);
			if (safeEqual(password, secret)) {
				const response = await next();
				const out = new Response(response.body, response);
				out.headers.set('X-Robots-Tag', 'noindex, nofollow');
				out.headers.set('Cache-Control', 'private, no-store');
				return out;
			}
		} catch (_) {
			// fall through to the login prompt
		}
	}

	return new Response('Password required.', {
		status: 401,
		headers: {
			'WWW-Authenticate': 'Basic realm="AL MASA preview", charset="UTF-8"',
			'Cache-Control': 'no-store',
			'X-Robots-Tag': 'noindex, nofollow',
		},
	});
}

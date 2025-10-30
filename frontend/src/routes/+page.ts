import type { PageLoad } from './$types';

export const load = (async ({ fetch }) => {
	try {
		// Use https://backend:8443 for internal Docker communication
		// NODE_TLS_REJECT_UNAUTHORIZED=0 allows self-signed certs
		const backendUrl = process.env.BACKEND_URL || 'https://backend:8443';

		const response = await fetch(`${backendUrl}/api/v1/events`);

		if (!response.ok) {
			console.error(`Failed to load events: ${response.status} ${response.statusText}`);
			throw new Error(`Failed to load events: ${response.statusText}`);
		}

		const events = await response.json();

		return {
			events
		};
	} catch (error) {
		console.error('Error loading events:', error);

		return {
			events: []
		};
	}
}) satisfies PageLoad;

import adapter from '@sveltejs/adapter-node';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		adapter: adapter({
			// Use a custom env variable for the origin
			// and make sure static files are served correctly
			out: 'build',
			precompress: false
		}),
		alias: {
			$components: 'src/components',
			$lib: 'src/lib',
		},
		paths: {
			// Ensure assets are served from the correct path
			assets: '',
		},
	},
};

export default config;

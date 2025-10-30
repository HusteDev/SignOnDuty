<script lang="ts">
	import type { PageData } from './$types';

	export let data: PageData;

	let selectedEvent: any = null;
	let signingMethod: 'mtls' | 'pades' = 'mtls';

	// Use events from server-side loader
	$: events = data.events || [];
	$: loading = false;

	async function handleMTLSSignup() {
		if (!selectedEvent) {
			alert('Please select an event');
			return;
		}

		try {
			// Use localhost for browser requests, backend:8443 for server-side
			const backendUrl = typeof window !== 'undefined' ? 'https://localhost:8443' : 'https://backend:8443';
			const response = await fetch(`${backendUrl}/api/v1/signups/mtls`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					event_name: selectedEvent.name,
					event_date: selectedEvent.start_date,
				}),
			});

			if (response.ok) {
				const data = await response.json();
				alert(`Sign-up successful! ID: ${data.signup_id}`);
			} else {
				const error = await response.json();
				alert(`Error: ${error.error}`);
			}
		} catch (error) {
			alert(`Failed to sign up: ${error}`);
		}
	}

	async function handlePAdESSignup() {
		if (!selectedEvent) {
			alert('Please select an event');
			return;
		}

		try {
			// Use localhost for browser requests, backend:8443 for server-side
			const backendUrl = typeof window !== 'undefined' ? 'https://localhost:8443' : 'https://backend:8443';
			const response = await fetch(`${backendUrl}/api/v1/signups/documents`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					event_id: selectedEvent.id,
					event_name: selectedEvent.name,
					event_date: selectedEvent.start_date,
					language: 'en',
				}),
			});

			if (response.ok) {
				const data = await response.json();
				// In production, would download PDF and redirect to signing UI
				console.log('Document generated:', data);
				alert('Document generated. Please download and sign with your CAC.');
			} else {
				const error = await response.json();
				alert(`Error: ${error.error}`);
			}
		} catch (error) {
			alert(`Failed to generate document: ${error}`);
		}
	}
</script>

<div class="min-h-screen bg-gray-50">
	<header class="bg-white shadow">
		<div class="max-w-7xl mx-auto px-4 py-6">
			<h1 class="text-3xl font-bold text-gray-900">SignOnDuty</h1>
			<p class="text-gray-600 mt-2">CAC-Authenticated Digital Sign-Up System</p>
		</div>
	</header>

	<main class="max-w-7xl mx-auto px-4 py-8">
		<div class="grid grid-cols-1 md:grid-cols-2 gap-8">
			{#if loading}
				<div class="col-span-full text-center py-12">
					<p class="text-gray-600">Loading events...</p>
				</div>
			{:else}
				<!-- Events List -->
				<div class="bg-white rounded-lg shadow p-6">
					<h2 class="text-2xl font-bold mb-4">Available Events</h2>
					<div class="space-y-3">
						{#each events as event (event.id)}
							<button
								on:click={() => (selectedEvent = event)}
								class={`w-full p-4 text-left rounded border-2 transition ${
									selectedEvent?.id === event.id
										? 'border-blue-500 bg-blue-50'
										: 'border-gray-200 hover:border-gray-300'
								}`}
							>
								<h3 class="font-semibold text-gray-900">{event.name}</h3>
								<p class="text-sm text-gray-600 mt-1">
									{new Date(event.start_date).toLocaleDateString()}
								</p>
								{#if event.location}
									<p class="text-sm text-gray-500">{event.location}</p>
								{/if}
							</button>
						{/each}
					</div>
				</div>

				<!-- Signing Methods -->
				{#if selectedEvent}
					<div class="bg-white rounded-lg shadow p-6">
						<h2 class="text-2xl font-bold mb-4">Sign In</h2>
						<div class="space-y-4">
							<div>
								<p class="font-semibold text-gray-900 mb-3">Select signing method:</p>
								<div class="space-y-3">
									<label class="flex items-center">
										<input
											type="radio"
											name="method"
											value="mtls"
											bind:group={signingMethod}
											class="w-4 h-4 text-blue-600"
										/>
										<span class="ml-3">
											<span class="font-medium">mTLS (Recommended)</span>
											<p class="text-sm text-gray-600">Sign with CAC certificate immediately</p>
										</span>
									</label>

									<label class="flex items-center">
										<input
											type="radio"
											name="method"
											value="pades"
											bind:group={signingMethod}
											class="w-4 h-4 text-blue-600"
										/>
										<span class="ml-3">
											<span class="font-medium">PAdES (Document Signing)</span>
											<p class="text-sm text-gray-600">Download PDF and sign with Acrobat</p>
										</span>
									</label>
								</div>
							</div>

							<button
								on:click={signingMethod === 'mtls' ? handleMTLSSignup : handlePAdESSignup}
								class="w-full bg-blue-600 text-white font-semibold py-3 rounded-lg hover:bg-blue-700 transition"
							>
								{#if signingMethod === 'mtls'}
									Sign In with CAC
								{:else}
									Generate Document
								{/if}
							</button>
						</div>

						<div class="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded">
							<p class="text-sm text-yellow-800">
								<strong>Note:</strong>
								{#if signingMethod === 'mtls'}
									Your CAC certificate will be used to authenticate and sign the record.
								{:else}
									You will receive a PDF that must be signed with your CAC in Adobe Acrobat or
									compatible software.
								{/if}
							</p>
						</div>
					</div>
				{:else}
					<div class="bg-gray-100 rounded-lg p-6">
						<p class="text-gray-600 text-center">Select an event to continue</p>
					</div>
				{/if}
			{/if}
		</div>
	</main>
</div>

<style>
	:global(body) {
		margin: 0;
		padding: 0;
	}
</style>

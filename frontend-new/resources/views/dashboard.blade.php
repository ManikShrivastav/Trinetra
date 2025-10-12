<!DOCTYPE html>
<html lang="en" class="scroll-smooth" x-data>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trinetra - Security Dashboard</title>
    
    <!-- Tailwind + custom fonts -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet"> -->
    @vite('resources/css/app.css')
    @vite('resources/js/app.js')
        <link rel="stylesheet" href="{{ asset('css/custom-color.css') }}">

    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body class="bg-[#0F111A] text-gray-100 font-['Arial']  min-h-screen flex transition-colors duration-500">
    
    @include('layouts.sidebar')

    <!-- Main Content -->
    <main class="flex-1 p-8 overflow-y-auto">
        <h1 class="text-4xl font-bold mb-2 text-cya-400">Security Dashboard</h1>
        <p class="text-gray-400 mb-6">Monitor your network security in real-time</p>

        <!-- Analytics Section -->
        <div class="grid md:grid-cols-2 gap-6 mb-8">
            <div class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-cya-500/50 hover:shadow-cya-400/80 transition">
                <h2 class="text-xl font-semibold mb-4 text-cya-400">Vulnerability Analytics</h2>
                <canvas id="vulnerabilityChart"></canvas>
            </div>

            <div class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-green-500/50 hover:shadow-green-400/80 transition">
                <h2 class="text-xl font-semibold mb-4 text-cya-400">Summary</h2>
                <div class="grid grid-cols-2 gap-4 mb-4">
                    <div>
                        <p class="text-2xl font-bold text-white">247</p>
                        <p class="text-sm text-gray-400">Total Scans</p>
                    </div>
                    <div>
                        <p class="text-2xl font-bold text-red-500">43</p>
                        <p class="text-sm text-gray-400">Critical Vulnerabilities</p>
                    </div>
                    <div>
                        <p class="text-2xl font-bold text-yellow-500">128</p>
                        <p class="text-sm text-gray-400">Medium Threats</p>
                    </div>
                    <div>
                        <p class="text-2xl font-bold text-green-500">76</p>
                        <p class="text-sm text-gray-400">Resolved Issues</p>
                    </div>
                </div>
                <p class="text-sm text-gray-400">
                    Network security improved by <span class="text-green-400 font-semibold">32%</span> this month.
                </p>
            </div>
        </div>

        <!-- Action Cards -->
        <div class="grid md:grid-cols-3 gap-6">
            <a href="/scan" class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-cya-500/50 hover:shadow-cya-400/80 transition transform hover:-translate-y-1">
                <h3 class="text-lg font-semibold mb-2 text-cya-400">New Scan</h3>
                <p class="text-sm text-gray-400">Initiate a comprehensive vulnerability scan.</p>
            </a>

            <a href="/past-scans" class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-magenta-500/50 hover:shadow-magenta-400/80 transition transform hover:-translate-y-1">
                <h3 class="text-lg font-semibold mb-2 text-cya-400">Past Scans</h3>
                <p class="text-sm text-gray-400">Review historical scan reports and trends.</p>
            </a>

            <a href="/bot" class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-green-500/50 hover:shadow-green-400/80 transition transform hover:-translate-y-1">
                <h3 class="text-lg font-semibold mb-2 text-cya-400">Security Bot</h3>
                <p class="text-sm text-gray-400">AI-powered assistance for remediation.</p>
            </a>
        </div>
    </main>

    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const ctx = document.getElementById('vulnerabilityChart');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [43, 62, 128, 14],
                    backgroundColor: '#3b82f6',
                    borderWidth: 1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: false } }
            }
        });
    </script>

    <!-- Theme Toggle JS -->
    <!-- <script src="{{ asset('js/theme-toggle.js') }}"></script> -->
    <!-- <script src="{{ asset('js/footer.js') }}"></script> -->
</body>
</html>

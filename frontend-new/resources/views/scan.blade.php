<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trinetra - Vulnerability Scan</title>

    <!-- Tailwind + Fonts -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    @vite('resources/css/app.css')
    @vite('resources/js/app.js')
    <link rel="stylesheet" href="{{ asset('css/custom-color.css') }}">
</head>

<body class="bg-[#0F111A] text-gray-100 font-['Arial']  min-h-screen flex transition-colors duration-500">

    @include('layouts.sidebar')

    <!-- Main Content -->
    <main class="flex-1 p-8 overflow-y-auto transition-colors duration-500 bg-white dark:bg-[#0F111A] text-black dark:text-gray-100">
        <h1 class="text-4xl font-bold mb-2 text-cya-400 dark:text-cya-400">Vulnerability Scan</h1>
        <p class="text-gray-600 dark:text-gray-400 mb-8">Enter a target IP or network range to begin your scan.</p>

        <!-- Scan Form -->
        <div class="bg-gray-100 dark:bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-8 shadow-cya-500/50 hover:shadow-cya-400/80 transition">
            <form id="scanForm" class="space-y-6">
                <div>
                    <label for="targetIp" class="block mb-2 text-gray-700 dark:text-gray-300 font-semibold">Target IP / Network</label>
                    <input type="text" id="targetIp" name="targetIp" placeholder="e.g., 192.168.1.1 or 192.168.1.0/24"
                        class="w-full p-3 rounded-md bg-white dark:bg-[#0F111A] border border-gray-300 dark:border-gray-700 focus:outline-none focus:ring-2 focus:ring-cya-500 text-black dark:text-gray-100 transition">
                </div>

                <div>
                    <label class="block mb-2 text-gray-700 dark:text-gray-300 font-semibold">Scanners </label>
                    <div class="grid md:grid-cols-3 gap-4">
                        <div class="flex items-center space-x-2">
                            <input type="checkbox" id="nmap" checked disabled class="accent-cya-500">
                            <label for="nmap">Nmap</label>
                        </div>
                        <div class="flex items-center space-x-2">
                            <input type="checkbox" id="nikto" checked disabled class="accent-cya-500">
                            <label for="nikto">Nikto</label>
                        </div>
                        <div class="flex items-center space-x-2">
                            <input type="checkbox" id="nuclei" checked disabled class="accent-cya-500">
                            <label for="nuclei">Nuclei</label>
                        </div>
                    </div>
                </div>

                <button type="submit"
                    class="flex items-center justify-center w-full md:w-auto px-6 py-3 bg-cya-500 text-black font-semibold rounded-md hover:bg-cya-400 shadow-cya-400/50 transition transform hover:-translate-y-1">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                        class="mr-2">
                        <polygon points="5 3 19 12 5 21 5 3"></polygon>
                    </svg>
                    Start Scan
                </button>
            </form>
        </div>

        <!-- Scan Progress Section -->
        <section id="scanProgressSection" class="hidden mt-10">
            <h2 class="text-2xl font-semibold mb-4 text-cya-400">Scanning in Progress</h2>
            <div class="space-y-4">
                <div class="bg-[#1B1E2C]/80 border border-cya-500 p-4 rounded-lg text-gray-300">
                    <p><strong>Target:</strong> <span id="scanTarget"></span></p>
                    <div id="progressBars" class="mt-4 space-y-3"></div>
                </div>
            </div>
        </section>

        <!-- Scan Results -->
        <section id="scanResultsSection" class="hidden mt-10">
            <h2 class="text-2xl font-semibold mb-4 text-cya-400">Scan Results</h2>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-[#1B1E2C]/80 border border-red-500 p-4 rounded-lg text-center">
                    <p class="text-3xl font-bold text-red-500" id="criticalCount">0</p>
                    <p class="text-sm text-gray-400">Critical</p>
                </div>
                <div class="bg-[#1B1E2C]/80 border border-orange-400 p-4 rounded-lg text-center">
                    <p class="text-3xl font-bold text-orange-400" id="highCount">0</p>
                    <p class="text-sm text-gray-400">High</p>
                </div>
                <div class="bg-[#1B1E2C]/80 border border-yellow-400 p-4 rounded-lg text-center">
                    <p class="text-3xl font-bold text-yellow-400" id="mediumCount">0</p>
                    <p class="text-sm text-gray-400">Medium</p>
                </div>
                <div class="bg-[#1B1E2C]/80 border border-green-500 p-4 rounded-lg text-center">
                    <p class="text-3xl font-bold text-green-500" id="lowCount">0</p>
                    <p class="text-sm text-gray-400">Low</p>
                </div>
            </div>

            <div id="vulnerabilitiesList" class="space-y-3"></div>

            <button id="newScanBtn"
                class="mt-6 bg-cya-500 text-black px-6 py-3 rounded-md font-semibold hover:bg-cya-400 transition transform hover:-translate-y-1">
                Start New Scan
            </button>
        </section>

    </main>


    <!-- Theme Toggle Script -->
    <!-- <script>
        const themeButton = document.getElementById('themeToggle');

        function applyTheme(theme) {
            document.documentElement.classList.toggle('dark', theme === 'dark');
            localStorage.setItem('theme', theme);
        }

        (function () {
            const saved = localStorage.getItem('theme') || 'dark';
            applyTheme(saved);
        })();

        themeButton.addEventListener('click', () => {
            const current = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
            applyTheme(current === 'dark' ? 'light' : 'dark');
        });
    </script> -->
    <!-- <script src="{{ asset('js/footer.js') }}"></script> -->

</body>
</html>

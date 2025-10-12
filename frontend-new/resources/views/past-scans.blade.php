<!-- resources/views/pastscans.blade.php -->
<!DOCTYPE html>
<html lang="en" class="scroll-smooth" x-data>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trinetra - Past Scans</title>
    
    <!-- Tailwind + custom fonts -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet">
    @vite('resources/css/app.css')
    @vite('resources/js/app.js')
    <link rel="stylesheet" href="{{ asset('css/custom-color.css') }}">
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body class="bg-[#0F111A] text-gray-100 font-['Arial']  min-h-screen flex transition-colors duration-500">
    
    @include('layouts.sidebar')

    <!-- Main Content -->
    <main class="flex-1 p-8 overflow-y-auto">
        <h1 class="text-4xl font-bold mb-2 text-cya-400">Past Scans</h1>
        <p class="text-gray-400 mb-6">Review historical vulnerability scan reports</p>

        <!-- Filters -->
        <!-- <div class="flex flex-wrap gap-4 mb-6">
            <input type="text" placeholder="Search by target IP..." class="p-2 rounded bg-[#1B1E2C]/80 border border-cya-500 text-white flex-1">
            <select class="p-2 rounded bg-[#1B1E2C]/80 border border-cya-500 text-white">
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
        </div> -->
        <div class="flex flex-wrap gap-4 mb-6">
    <input 
        type="text" 
        placeholder="Search by target IP..." 
        class="flex-1 p-3 rounded-lg bg-[#1B1E2C]/80 border border-cya-500 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cya-400 focus:border-cya-400 transition"
    >

    <div class="relative">
        <select 
            class="appearance-none p-3 rounded-lg bg-[#1B1E2C]/80 border border-cya-500 text-white focus:outline-none focus:ring-2 focus:ring-cya-400 focus:border-cya-400 transition pr-10"
        >
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
        </select>
        <!-- Custom arrow -->
        <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-3">
            <svg class="w-4 h-4 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 111.06 1.06l-4.24 4.24a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.06z" clip-rule="evenodd" />
            </svg>
        </div>
    </div>
</div>



        <!-- Scan Cards -->
        <div class="grid md:grid-cols-2 gap-6">
            <!-- Scan 1 -->
            <div class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-cya-500/50 hover:shadow-cya-400/80 transition">
                <div class="flex justify-between items-center mb-4">
                    <div>
                        <h2 class="text-xl font-semibold">192.168.1.100</h2>
                        <p class="text-gray-400 text-sm">2025-10-02 14:32:18</p>
                    </div>
                    <span class="px-2 py-1 bg-red-600 text-white rounded">Critical</span>
                </div>
                <div class="grid grid-cols-4 gap-2 text-center mb-4">
                    <div><strong class="text-red-500">8</strong> Crit</div>
                    <div><strong class="text-orange-400">15</strong> High</div>
                    <div><strong class="text-yellow-400">23</strong> Med</div>
                    <div><strong class="text-green-500">12</strong> Low</div>
                </div>
                <p class="text-gray-400 text-sm">Multiple critical vulnerabilities detected including outdated SSL/TLS protocols, unpatched services, and open administrative ports.</p>
            </div>

            <!-- Scan 2 -->
            <div class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-magenta-500/50 hover:shadow-magenta-400/80 transition">
                <div class="flex justify-between items-center mb-4">
                    <div>
                        <h2 class="text-xl font-semibold">10.0.0.50</h2>
                        <p class="text-gray-400 text-sm">2025-10-01 09:15:42</p>
                    </div>
                    <span class="px-2 py-1 bg-orange-600 text-white rounded">High</span>
                </div>
                <div class="grid grid-cols-4 gap-2 text-center mb-4">
                    <div><strong class="text-red-500">2</strong> Crit</div>
                    <div><strong class="text-orange-400">11</strong> High</div>
                    <div><strong class="text-yellow-400">18</strong> Med</div>
                    <div><strong class="text-green-500">9</strong> Low</div>
                </div>
                <p class="text-gray-400 text-sm">Web server vulnerabilities detected with SQL injection possibilities and cross-site scripting risks.</p>
            </div>

            <!-- Scan 3 -->
            <div class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-green-500/50 hover:shadow-green-400/80 transition">
                <div class="flex justify-between items-center mb-4">
                    <div>
                        <h2 class="text-xl font-semibold">172.16.0.25</h2>
                        <p class="text-gray-400 text-sm">2025-09-30 16:48:03</p>
                    </div>
                    <span class="px-2 py-1 bg-yellow-500 text-white rounded">Medium</span>
                </div>
                <div class="grid grid-cols-4 gap-2 text-center mb-4">
                    <div><strong class="text-red-500">0</strong> Crit</div>
                    <div><strong class="text-orange-400">3</strong> High</div>
                    <div><strong class="text-yellow-400">14</strong> Med</div>
                    <div><strong class="text-green-500">22</strong> Low</div>
                </div>
                <p class="text-gray-400 text-sm">Moderate security concerns with outdated software versions and missing security headers.</p>
            </div>

            <!-- Scan 4 -->
            <div class="bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-6 shadow-blue-500/50 hover:shadow-blue-400/80 transition">
                <div class="flex justify-between items-center mb-4">
                    <div>
                        <h2 class="text-xl font-semibold">192.168.1.0/24</h2>
                        <p class="text-gray-400 text-sm">2025-09-28 11:22:56</p>
                    </div>
                    <span class="px-2 py-1 bg-green-600 text-white rounded">Low</span>
                </div>
                <div class="grid grid-cols-4 gap-2 text-center mb-4">
                    <div><strong class="text-red-500">0</strong> Crit</div>
                    <div><strong class="text-orange-400">1</strong> High</div>
                    <div><strong class="text-yellow-400">5</strong> Med</div>
                    <div><strong class="text-green-500">18</strong> Low</div>
                </div>
                <p class="text-gray-400 text-sm">Network segment scan shows minimal security concerns with minor configuration improvements recommended.</p>
            </div>
        </div>
    </main>
        <!-- <script src="{{ asset('js/footer.js') }}"></script> -->

</body>
</html>

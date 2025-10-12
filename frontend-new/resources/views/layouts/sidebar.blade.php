<aside class="w-64 bg-white dark:bg-[#0F111A] text-black dark:text-gray-100 shadow-lg flex flex-col justify-between border-r border-gray-200 dark:border-gray-700 transition-colors duration-500">
    <div>
        <!-- Logo & Tagline -->
        <div class="p-6 text-center border-b border-gray-300 dark:border-gray-700">
            <h1 class="text-2xl font-bold text-cya-500 dark:text-cya-400">Trinetra</h1>
            <p class="text-sm text-gray-600 dark:text-gray-400">The Eye That Never Blinks</p>
        </div>

        <!-- User Info -->
         @if($user)
        <div class="p-4 text-center border-b border-gray-300 dark:border-gray-700">
            <h2 class="font-semibold text-lg">{{ strtoupper( $user->name ) }}</h2>
            <p class="text-sm text-gray-600 dark:text-gray-400">{{ strtoupper($user->role_name ) }}</p>
        </div>
        @endif

        <!-- Navigation -->
        @php
            $currentRoute = request()->path();
        @endphp
        <nav class="flex flex-col p-4 space-y-2">
            <a href="/dashboard" class="flex items-center px-4 py-2 rounded-md transition 
                {{ $currentRoute == 'dashboard' ? 'bg-cya-500 text-black dark:bg-cya-400 dark:text-black' : 'hover:bg-cyan-100 dark:hover:bg-cyan-700/50' }}">
                <svg class="w-5 h-5 mr-2 text-magenta-400 dark:text-magenta-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path d="M4 4h6v6H4z M14 4h6v6h-6z M4 14h6v6H4z M14 14h6v6h-6z"/>
                </svg>
                Dashboard
            </a>

            <a href="/scan" class="flex items-center px-4 py-2 rounded-md transition
                {{ $currentRoute == 'scan' ? 'bg-cya-500 text-black dark:bg-cya-400 dark:text-black' : 'hover:bg-cyan-100 dark:hover:bg-cyan-700/50' }}">
                <svg class="w-5 h-5 mr-2 text-magenta-400 dark:text-magenta-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <circle cx="11" cy="11" r="7" stroke-width="2"/>
                    <line x1="16.65" y1="16.65" x2="21" y2="21" stroke-width="2"/>
                </svg>
                Scan
            </a>

            <a href="/past-scans" class="flex items-center px-4 py-2 rounded-md transition
                {{ $currentRoute == 'past-scans' ? 'bg-cya-500 text-black dark:bg-cya-400 dark:text-black' : 'hover:bg-cyan-100 dark:hover:bg-cyan-700/50' }}">
                <svg class="w-5 h-5 mr-2 text-magenta-500 dark:text-magenta-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <circle cx="12" cy="12" r="9" stroke-width="2"/>
                    <line x1="12" y1="7" x2="12" y2="12" stroke-width="2"/>
                    <line x1="12" y1="12" x2="15" y2="15" stroke-width="2"/>
                </svg>
                Past Scans
            </a>

            <a href="/bot" class="flex items-center px-4 py-2 rounded-md transition
                {{ $currentRoute == 'bot' ? 'bg-cya-500 text-black dark:bg-cya-400 dark:text-black' : 'hover:bg-cyan-100 dark:hover:bg-cyan-700/50' }}">
                <svg class="w-5 h-5 mr-2 text-magenta-400 dark:text-magenta-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <circle cx="12" cy="12" r="10"/>
                    <circle cx="12" cy="12" r="4"/>
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                    <line x1="19.07" y1="4.93" x2="4.93" y2="19.07"/>
                </svg>
                Bot
            </a>
        </nav>
    </div>

    <!-- Bottom Settings -->
    <div class="p-4 border-t border-gray-300 dark:border-gray-700 space-y-2">
        <!-- <button id="themeToggle" class="w-full bg-gray-200 dark:bg-gray-800 text-black dark:text-gray-200 rounded-md py-2 hover:bg-gray-300 dark:hover:bg-gray-700 transition">
            Toggle Theme
        </button> -->

        <form action="{{ route('logout') }}" method="POST">
            @csrf
            <button class="w-full bg-red-600 text-white rounded-md py-2 hover:bg-red-700 transition">
                Logout
            </button>
        </form>
    </div>
</aside>

<!DOCTYPE html>
<html lang="en" class="scroll-smooth" x-data>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trinetra - Security Bot</title>

    <!-- Tailwind + custom fonts -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap" rel="stylesheet"> -->
    @vite('resources/css/app.css')
    @vite('resources/js/app.js')
    <link rel="stylesheet" href="{{ asset('css/custom-color.css') }}">

    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body class="bg-[#0F111A] text-gray-100 font-['Arial'] min-h-screen flex transition-colors duration-500">

    @include('layouts.sidebar') <!-- Sidebar with username and role -->

    <!-- Main Content -->
    <main class="flex-1 p-8 overflow-y-auto flex flex-col">
        <h1 class="text-4xl font-bold mb-2 text-cya-400">Security Assistant Bot</h1>
        <p class="text-gray-400 mb-6">Get AI-powered recommendations for vulnerability remediation</p>

        <!-- Chat Container -->
        <div class="flex-1 flex flex-col bg-[#1B1E2C]/80 backdrop-blur-md border border-cya-500 rounded-lg p-4 shadow-cya-500/50 transition max-h-[70vh]">
            
            <!-- Chat Messages -->
            <div id="chatMessages" class="flex-1 overflow-y-auto mb-4 p-2 space-y-4">
                <!-- First Bot Message -->
                <div class="message bot-message p-4 rounded-md bg-[#212439]/80">
                    <p class="font-semibold text-cya-400">Security Bot:</p>
                    <p>Hello! I'm your security assistant. I can help you understand vulnerabilities found in your scans and provide remediation guidance. How can I assist you today?</p>
                </div>
            </div>

            <!-- Input Field -->
            <form id="chatForm" class="flex mt-auto gap-2">
                <input 
                    type="text" 
                    id="chatInput" 
                    class="flex-1 p-3 rounded-md bg-[#212439]/80 text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cya-400" 
                    placeholder="Ask about vulnerabilities, remediation steps, or security best practices..."
                >
                <button type="submit" class="px-4 py-3 bg-cya-500 text-black rounded-md hover:bg-cya-400 transition">Send</button>
            </form>
        </div>
    </main>

    <!-- <script src="{{ asset('js/bot.js') }}"></script>
    <script src="{{ asset('js/footer.js') }}"></script> -->
</body>
</html>

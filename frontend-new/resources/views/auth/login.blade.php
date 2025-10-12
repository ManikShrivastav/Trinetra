<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
  

    <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Trinetra | Login</title>

    <!-- <link rel="stylesheet" href="{{ asset('css/tailwind.17.css') }}"> -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="{{ asset('css/custom-color.css') }}">

    <!-- @vite('resources/css/custom-color.css') {{-- This loads Tailwind CSS --}} -->
    @vite('resources/js/app.js')   {{-- Optional: if you have main JS file --}}
    <!-- @vite('resources/js/components/captcha.js')   {{-- Optional: if you have main JS file --}} -->


    <link rel="icon" type="image/png" href="https://img.icons8.com/?size=100&id=85726&format=png&color=00FFFF"/>
</head>

   

  <body
    class="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-black relative overflow-hidden transition-colors duration-500"
  >
    <canvas id="matrix" class="absolute inset-0 z-0"></canvas>

    <div
      class="relative z-10 w-full max-w-md p-8 bg-white/90 dark:bg-gray-900/80 backdrop-blur-xl rounded-2xl shadow-2xl border border-cya-500/30 transition-all duration-500"
    >
      <h1
        class="text-3xl font-extrabold text-center mb-2 text-gray-900 text-cya-400 tracking-wide"
      >
        TRINETRA
      </h1>
      <!-- <p class="text-center text-gray-500 dark:text-gray-400 mb-6">Centralized Vulnerability Detection & Intelligent Query Interface</p> -->

      <form id="loginForm" class="space-y-5" action="{{ route('login.post') }}" method="POST">
        @csrf

        @if ($errors->any())
    <div class="text-red-500 mt-2">
        @foreach ($errors->all() as $error)
            <p>{{ $error }}</p>
        @endforeach
    </div>
@endif
        <div>
          <label
            for="userId"
            class="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >User ID</label
          >
          <input
            type="text"
            id="userId"
            name="userid"
            required
            
            class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
          />
        </div>

        <div>
          <label
            for="password"
            class="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >Password</label
          >
          <input
            type="password"
            id="password"
            name="password"
            placeholder="Enter Password" autocomplete="off"
            required
            class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
          />
        </div>

        <div>
          <label
            for="role"
            class="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >Role</label
          >
          <select
            id="role"
            name="role_id"
            required
            class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
          >
           @foreach($roles as $role)
        <option value="{{ $role->id }}">{{ ucfirst($role->name) }}</option>
    @endforeach
          </select>
        </div>

        <!-- CAPTCHA Section -->
        <!-- <div>
          <label
            class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
            >Security Check</label
          >
          <div class="flex items-center space-x-3">
            <canvas
              id="captchaCanvas"
              width="120"
              height="40"
              class="border border-cya-400 rounded-lg bg-gray-100 dark:bg-gray-800 text-center"
            ></canvas>
            <button
              type="button"
              id="refreshCaptcha"
              class="text-cya-600 dark:text-cya-400 hover:underline text-sm"
            >
              ↻ Refresh
            </button>
          </div>
          <input
            type="text"
            id="captchaInput"
            name="captcha"
            required
            placeholder="Enter the code"
            class="w-full mt-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
          />
        </div> -->

        <button
          type="submit"
          class="w-full py-2.5 font-semibold text-lg text-white bg-cya-600 hover:bg-cya-500 rounded-lg shadow-lg transition-all duration-300 focus:ring-4 focus:ring-cya-400"
        >
          Login
        </button>
      </form>

      <p class="text-center mt-6 text-gray-600 dark:text-gray-400">
        Don’t have an account?
        <a
          href="{{ route('register') }}"
          class="text-cya-600 dark:text-cya-400 hover:underline font-medium"
          >Sign up here</a
        >
       

      </p>
    </div>

<script src="{{ asset('js/footer-auth.js') }}"></script>
  </body>
</html>

<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Trinetra | Register</title>

    <!-- TailwindCSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="{{ asset('css/custom-color.css') }}">

    @vite('resources/js/app.js')

    <link rel="icon" type="image/png" href="https://img.icons8.com/?size=100&id=85726&format=png&color=00FFFF"/>
</head>

<body class="min-h-screen flex items-start justify-center pt-12 pb-12 bg-gray-100 dark:bg-black relative overflow-y-auto transition-colors duration-500">
    <canvas id="matrix" class="absolute inset-0 z-0"></canvas>

    <div class="relative z-10 w-full max-w-md p-8 bg-white/90 dark:bg-gray-900/80 backdrop-blur-xl rounded-2xl shadow-2xl border border-cya-500/30 transition-all duration-500 flex-shrink-0">
          <h1 class="text-3xl font-extrabold text-center mb-2 text-gray-900 text-cya-400 tracking-wide">
            TRINETRA
        </h1>
        <p class="text-center text-gray-500 dark:text-gray-400 mb-6">
            Create your account
        </p>

        @if ($errors->any())
            <div class="bg-red-500/10 border border-red-400 text-red-500 text-sm p-3 rounded-lg mb-4">
                <ul class="list-disc list-inside">
                    @foreach ($errors->all() as $error)
                        <li>{{ $error }}</li>
                    @endforeach
                </ul>
            </div>
        @endif


        @if (session('success') && session('userid'))
    <div style="background-color:#3b82f6; color:white; padding:12px; border-radius:6px; margin-bottom:20px; text-align:center;">
        {{ session('success') }} <br>
        <strong>Your User ID: {{ session('userid') }}</strong>
    </div>
@endif

        <form method="POST" action="{{ route('register.post') }}" class="space-y-5">
            @csrf

            <div>
                <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Full Name</label>
                <input type="text" id="name" name="name" required
                       class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
                       placeholder="John Doe" value ="" />
            </div>

            <div>
                <label for="userid" class="block text-sm font-medium text-gray-700 dark:text-gray-300">User ID</label>
                <input type="text" id="userid" name="userid" required
                       class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
                       placeholder="Will be assigned automatically!" disabled />
            </div>

            <div>
                <label for="email" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Email</label>
                <input type="email" id="email" name="email" required
                       class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
                       placeholder="you@example.com" value =""/>
            </div>

            <div>
                <label for="role_id" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Role</label>
                <select id="role_id" name="role_id" required
                        class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition">
                    <option value="">Select Role</option>
                    @foreach($roles as $role)
                        <option value="{{ $role->id }}">{{ ucfirst($role->name) }}</option>
                    @endforeach
                </select>
            </div>

            <div>
                <label for="password" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
                <input type="password" id="password" name="password" required
                       class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
                       placeholder="********" />
            </div>

            <div>
                <label for="password_confirmation" class="block text-sm font-medium text-gray-700 dark:text-gray-300">Confirm Password</label>
                <input type="password" id="password_confirmation" name="password_confirmation" required
                       class="w-full mt-1 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-cya-400 outline-none transition"
                       placeholder="********" />
            </div>

            <button type="submit"
                    class="w-full py-2.5 font-semibold text-lg text-white bg-cya-600 hover:bg-cya-500 rounded-lg shadow-lg transition-all duration-300 focus:ring-4 focus:ring-cya-400">
                Sign Up
            </button>
        </form>

        <p class="text-center mt-6 text-gray-600 dark:text-gray-400">
            Already have an account?
            <a href="{{ route('login') }}" class="text-cya-600 dark:text-cya-400 hover:underline font-medium">
                Login here
            </a>
        </p>
    </div>

    <script src="{{ asset('js/footer-auth.js') }}"></script>
</body>
</html>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard | Trinetra</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 dark:bg-black text-gray-900 dark:text-white p-10">

    <h1 class="text-3xl font-bold mb-5">Welcome, {{ $user->name }}</h1>

    <div class="space-y-2">
        <p><strong>User ID:</strong> {{ $user->userid }}</p>
        <p><strong>Email:</strong> {{ $user->email }}</p>
        <p><strong>Role:</strong> {{ ucfirst($user->role_name) }}</p>
        <p><strong>Created On:</strong> {{ $user->created_at }}</p>
        <p><strong>Last Accessed:</strong> {{ $user->last_accessed }}</p>
    </div>

    <form action="{{ route('logout') }}" method="POST" class="mt-5">
        @csrf
        <button type="submit" class="px-4 py-2 bg-cya-600 rounded text-white hover:bg-cya-500">Logout</button>
    </form>
</body>
</html>

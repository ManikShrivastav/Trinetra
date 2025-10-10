<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Trinetra — Initializing</title>
        <meta name="csrf-token" content="{{ csrf_token() }}">

    <link href="{{ asset('css/app.css') }}" rel="stylesheet">
    <style>
        body {
            @apply bg-black text-white flex items-center justify-center h-screen;
        }
        .spinner {
            width: 80px;
            height: 80px;
            border: 6px solid #1f2937; /* dark grey border */
            border-top-color: #3b82f6; /* Trinetra blue */
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-top: 20rem;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .loading-text {
            font-size: 1.2rem;
            color: #3b82f6;
            font-family: 'Orbitron', sans-serif;
            letter-spacing: 2px;
        }
    </style>
</head>
<body>
   <body>
  <!-- Fullscreen Loader Overlay -->
  <div id="loader" class="fixed inset-0 flex flex-col items-center justify-center bg-black z-50">
    <div class="spinner"></div>
    <div class="loading-text">Initializing Trinetra System...</div>
  </div>



      <script>
        setTimeout(() => {
            fetch('/check-session', {
                method: 'GET',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                },
                credentials: 'same-origin' // important for Laravel session
            })
        //     .then(response => {
        //         if (!response.ok) throw new Error('Network response not ok');
        //         return response.json();
        //     })
        //     .then(data => {
        //         if (data.logged_in) {
        //             window.location.href = '/dashboard';
        //         } else {
        //             window.location.href = '/dashboard';
        //         }
        //     })
        //     .catch(err => {
        //         console.error('AJAX error:', err);
        //         window.location.href = '/500'; // send to 500 error page
        //     });
        // }, 1200); // small delay for spinner

        .then(async response => {
        // Parse JSON, even if response is an error
        const data = await response.json().catch(() => null);

        if (!response.ok) {
            const errorMsg = data?.error || 'Unknown server error';
            console.error('Server returned error:', errorMsg);
            alert('Server Error: ' + errorMsg); // Optional: show on screen
            throw new Error(errorMsg);
        }

        if (data.logged_in) {
            window.location.href = '/dashboard';
        } else {
            window.location.href = '/dashboard';
        }
    })
    .catch(err => {
        console.error('AJAX error:', err.message);
        // Optionally redirect
        window.location.href = '/500';
    });
}, 1200);
    </script>

</body>
</html>

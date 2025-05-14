// Authentication and authorization functionality
document.addEventListener('DOMContentLoaded', function() {
    const initialsInput = document.getElementById('initials');
    const enterButton = document.getElementById('enter-button');
    const disclaimerModal = document.getElementById('disclaimer-modal');
    const content = document.getElementById('content');

    // Enable/disable enter button based on initials input
    initialsInput.addEventListener('input', function() {
        enterButton.disabled = this.value.length < 2;
    });

    // Handle enter button click
    enterButton.addEventListener('click', function() {
        // Store user initials in session storage
        sessionStorage.setItem('userInitials', initialsInput.value);
        
        // Hide disclaimer and show content
        disclaimerModal.style.display = 'none';
        content.classList.add('show-content');
        
        // Trigger matrix animation fade out
        const overlay = document.getElementById('matrix-overlay');
        overlay.classList.add('fade-out');
        setTimeout(() => {
            overlay.style.display = 'none';
        }, 1000);
    });
});

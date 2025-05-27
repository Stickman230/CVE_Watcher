document.addEventListener('DOMContentLoaded', () => {
    const el = document.getElementById('description');
    const divHeight = +el.offsetHeight

    const lineHeight = +el.style.lineHeight.replace('px', '');

    const lines = divHeight / lineHeight;
    console.log(lines);
    
    if (lines >= 8) {
        const vector_el = document.getElementById('vector');
        vector_el.style.display = 'none';
    }
});



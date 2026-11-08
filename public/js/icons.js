        (function generateAppIcons() {
            try {
                const canvas = document.createElement('canvas');
                canvas.width = 512;
                canvas.height = 512;
                const ctx = canvas.getContext('2d');

                const grad = ctx.createLinearGradient(0, 0, 512, 512);
                grad.addColorStop(0, '#4f46e5');
                grad.addColorStop(1, '#7e22ce');
                ctx.fillStyle = grad;
                ctx.beginPath();
                ctx.roundRect(0, 0, 512, 512, 115);
                ctx.fill();

                ctx.fillStyle = 'rgba(255,255,255,0.15)';
                ctx.beginPath();
                ctx.roundRect(96, 140, 320, 232, 40);
                ctx.fill();

                ctx.strokeStyle = '#ffffff';
                ctx.lineWidth = 28;
                ctx.beginPath();
                ctx.roundRect(106, 150, 300, 212, 36);
                ctx.stroke();

                ctx.fillStyle = '#10b981';
                ctx.beginPath();
                ctx.roundRect(310, 216, 110, 80, 24);
                ctx.fill();

                ctx.fillStyle = '#ffffff';
                ctx.beginPath();
                ctx.arc(350, 256, 14, 0, Math.PI * 2);
                ctx.fill();

                const pngUrl = canvas.toDataURL('image/png');
                document.getElementById('dynamic-favicon').href = pngUrl;
                document.getElementById('dynamic-apple-icon').href = pngUrl;
            } catch (e) {}
        })();

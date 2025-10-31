// Tab switching function
function openTab(evt, tabName) {
    // Hide all tab content
    const tabContents = document.getElementsByClassName('tab-content');
    for (let i = 0; i < tabContents.length; i++) {
        tabContents[i].classList.remove('active');
    }
    
    // Remove active class from all buttons
    const tabButtons = document.getElementsByClassName('tab-button');
    for (let i = 0; i < tabButtons.length; i++) {
        tabButtons[i].classList.remove('active');
    }
    
    // Show current tab and mark button as active
    document.getElementById(tabName).classList.add('active');
    evt.currentTarget.classList.add('active');
}

// Wait for DOM to load
document.addEventListener('DOMContentLoaded', function() {
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        const severityData = {
            critical: parseInt(document.querySelector('.stat-card.critical .stat-number').textContent) || 0,
            high: parseInt(document.querySelector('.stat-card.high .stat-number').textContent) || 0,
            medium: parseInt(document.querySelector('.stat-card.medium .stat-number').textContent) || 0,
            low: parseInt(document.querySelector('.stat-card.low .stat-number').textContent) || 0
        };
        
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [severityData.critical, severityData.high, severityData.medium, severityData.low],
                    backgroundColor: ['#dc2626', '#ea580c', '#f59e0b', '#84cc16'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Findings by Severity',
                        font: { size: 18, weight: 'bold' },
                        padding: { top: 10, bottom: 20 },
                        color: '#1e293b'
                    },
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 13, weight: '500' },
                            color: '#475569',
                            usePointStyle: true,
                            pointStyle: 'circle',
                            generateLabels: function(chart) {
                                const data = chart.data;
                                if (data.labels.length && data.datasets.length) {
                                    return data.labels.map((label, i) => {
                                        const value = data.datasets[0].data[i];
                                        return {
                                            text: `${label}: ${value}`,
                                            fillStyle: data.datasets[0].backgroundColor[i],
                                            hidden: false,
                                            index: i
                                        };
                                    });
                                }
                                return [];
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
});

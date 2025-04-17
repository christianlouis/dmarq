/**
 * Dashboard page functionality
 */

async function renderDashboard() {
    // Verify authentication
    if (!appState.isAuthenticated) {
        router.navigate('/login');
        return;
    }
    
    const appElement = document.getElementById('app');
    
    // Create dashboard layout
    appElement.innerHTML = `
        <div class="navbar">
            <div class="logo">DMARQ</div>
            <div class="user-menu">
                <button id="logout-button">Logout</button>
            </div>
        </div>
        
        <div class="sidebar">
            <ul>
                <li><a href="/dashboard" data-route>Dashboard</a></li>
                <li><a href="/domains" data-route>Domains</a></li>
                <li><a href="/reports" data-route>Reports</a></li>
                <li><a href="/settings" data-route>Settings</a></li>
            </ul>
        </div>
        
        <div class="main-content">
            <h1>Dashboard</h1>
            
            <div id="loading-dashboard">Loading dashboard data...</div>
            
            <div id="dashboard-content" class="hidden">
                <div class="dashboard-stats">
                    <div class="card">
                        <h3>Total Domains</h3>
                        <div id="total-domains" class="stat">-</div>
                    </div>
                    
                    <div class="card">
                        <h3>Total Reports</h3>
                        <div id="total-reports" class="stat">-</div>
                    </div>
                    
                    <div class="card">
                        <h3>Compliance Rate</h3>
                        <div id="compliance-rate" class="stat">-</div>
                    </div>
                </div>
                
                <div class="card">
                    <h2>Compliance Overview</h2>
                    <div class="chart-container">
                        <canvas id="compliance-chart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <h2>Recent Reports</h2>
                    <div id="recent-reports">
                        <table>
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Date</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody id="reports-table-body">
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add event listener for logout
    document.getElementById('logout-button').addEventListener('click', () => {
        api.auth.logout();
    });
    
    try {
        // Load dashboard data
        await loadDashboardData();
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showError('Failed to load dashboard data');
    }
}

async function loadDashboardData() {
    try {
        // Fetch domains and reports data
        const [domainsResponse, reportsResponse] = await Promise.all([
            api.domains.getAll(),
            api.reports.getAll()
        ]);
        
        const domains = domainsResponse || [];
        const reports = reportsResponse || [];
        
        // Update stats
        document.getElementById('total-domains').textContent = domains.length;
        document.getElementById('total-reports').textContent = reports.length;
        
        // Calculate compliance rate
        const compliantReports = reports.filter(report => report.is_compliant);
        const complianceRate = reports.length > 0 
            ? Math.round((compliantReports.length / reports.length) * 100) 
            : 0;
        document.getElementById('compliance-rate').textContent = `${complianceRate}%`;
        
        // Render compliance chart
        renderComplianceChart(reports);
        
        // Render recent reports table
        renderRecentReports(reports, domains);
        
        // Hide loading, show content
        document.getElementById('loading-dashboard').classList.add('hidden');
        document.getElementById('dashboard-content').classList.remove('hidden');
    } catch (error) {
        throw new Error('Failed to load dashboard data');
    }
}

function renderComplianceChart(reports) {
    if (!reports || reports.length === 0) return;
    
    const canvas = document.getElementById('compliance-chart');
    if (!canvas) return;
    
    // Prepare data
    const last6Months = [];
    const currentDate = new Date();
    
    for (let i = 5; i >= 0; i--) {
        const date = new Date(currentDate);
        date.setMonth(currentDate.getMonth() - i);
        const monthName = date.toLocaleString('default', { month: 'short' });
        last6Months.push({
            month: monthName,
            year: date.getFullYear(),
            reports: [],
            startDate: new Date(date.getFullYear(), date.getMonth(), 1),
            endDate: new Date(date.getFullYear(), date.getMonth() + 1, 0)
        });
    }
    
    // Group reports by month
    reports.forEach(report => {
        const reportDate = new Date(report.report_date);
        const monthData = last6Months.find(monthInfo => 
            reportDate >= monthInfo.startDate && reportDate <= monthInfo.endDate
        );
        
        if (monthData) {
            monthData.reports.push(report);
        }
    });
    
    // Calculate compliance rates by month
    const complianceData = last6Months.map(monthInfo => {
        if (monthInfo.reports.length === 0) return 0;
        const compliantCount = monthInfo.reports.filter(report => report.is_compliant).length;
        return Math.round((compliantCount / monthInfo.reports.length) * 100);
    });
    
    const labels = last6Months.map(monthInfo => `${monthInfo.month} ${monthInfo.year}`);
    
    // Create chart
    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Compliance Rate (%)',
                data: complianceData,
                backgroundColor: '#3b82f6',
                borderColor: '#2563eb',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Compliance Rate (%)'
                    }
                }
            }
        }
    });
}

function renderRecentReports(reports, domains) {
    if (!reports || reports.length === 0) return;
    
    const tableBody = document.getElementById('reports-table-body');
    if (!tableBody) return;
    
    // Sort reports by date (newest first) and take last 10
    const sortedReports = [...reports]
        .sort((a, b) => new Date(b.report_date) - new Date(a.report_date))
        .slice(0, 10);
    
    // Create a lookup map for domains
    const domainMap = new Map();
    domains.forEach(domain => {
        domainMap.set(domain.id, domain.domain_name);
    });
    
    // Add rows to the table
    sortedReports.forEach(report => {
        const row = document.createElement('tr');
        
        // Format date
        const reportDate = new Date(report.report_date);
        const formattedDate = reportDate.toLocaleDateString();
        
        // Get domain name
        const domainName = domainMap.get(report.domain_id) || 'Unknown';
        
        row.innerHTML = `
            <td>${domainName}</td>
            <td>${formattedDate}</td>
            <td>${report.is_compliant ? 
                '<span style="color: green;">Compliant</span>' : 
                '<span style="color: red;">Non-compliant</span>'
            }</td>
        `;
        
        tableBody.appendChild(row);
    });
}
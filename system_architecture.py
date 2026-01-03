"""
System Architecture Visualization for Vulnerability Management System
Creates diagrams showing how the system addresses each organizational roadblock
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
import numpy as np

def create_architecture_diagram():
    """Create comprehensive system architecture diagram"""
    
    fig, ax = plt.subplots(1, 1, figsize=(16, 12))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis('off')
    
    # Title
    ax.text(5, 9.5, 'Bedrock AgentCore Vulnerability Management System', 
            fontsize=18, fontweight='bold', ha='center')
    
    # Main orchestrator
    orchestrator = FancyBboxPatch((4, 8), 2, 0.8, 
                                  boxstyle="round,pad=0.1", 
                                  facecolor='lightblue', 
                                  edgecolor='navy', linewidth=2)
    ax.add_patch(orchestrator)
    ax.text(5, 8.4, 'VM Orchestrator', fontsize=12, fontweight='bold', ha='center')
    
    # Specialized agents in a circle around orchestrator
    agents = [
        ('Asset Discovery\nAgent', 1.5, 7, 'lightgreen', 'Eliminates\nBlind Spots'),
        ('Risk Prioritization\nAgent', 1.5, 5, 'orange', 'Reduces\nOverwhelm'),
        ('Resource Optimization\nAgent', 1.5, 3, 'yellow', 'Maximizes\nROI'),
        ('Collaboration\nAgent', 8.5, 3, 'pink', 'Breaks Down\nSilos'),
        ('Strategic Planning\nAgent', 8.5, 5, 'lightcoral', 'Enables\nProactive'),
        ('Legacy Systems\nAgent', 8.5, 7, 'lightgray', 'Manages\nTech Debt'),
        ('Patch Management\nAgent', 5, 6, 'lightcyan', 'Accelerates\nDeployment')
    ]
    
    for name, x, y, color, benefit in agents:
        # Agent box
        agent_box = FancyBboxPatch((x-0.7, y-0.4), 1.4, 0.8,
                                   boxstyle="round,pad=0.05",
                                   facecolor=color,
                                   edgecolor='black')
        ax.add_patch(agent_box)
        ax.text(x, y, name, fontsize=9, fontweight='bold', ha='center', va='center')
        
        # Benefit annotation
        ax.text(x, y-0.8, benefit, fontsize=8, ha='center', va='center', 
                style='italic', color='darkblue')
        
        # Connection to orchestrator
        ax.annotate('', xy=(5, 8), xytext=(x, y+0.4),
                   arrowprops=dict(arrowstyle='->', color='gray', alpha=0.6))
    
    # Memory and tools at bottom
    memory_box = FancyBboxPatch((1, 1), 2, 0.8,
                                boxstyle="round,pad=0.1",
                                facecolor='lavender',
                                edgecolor='purple')
    ax.add_patch(memory_box)
    ax.text(2, 1.4, 'AgentCore Memory', fontsize=10, fontweight='bold', ha='center')
    ax.text(2, 1.1, '• Asset Knowledge\n• Vuln History\n• Process Learning', 
            fontsize=8, ha='center')
    
    tools_box = FancyBboxPatch((7, 1), 2, 0.8,
                               boxstyle="round,pad=0.1", 
                               facecolor='lightyellow',
                               edgecolor='orange')
    ax.add_patch(tools_box)
    ax.text(8, 1.4, 'Code Interpreter', fontsize=10, fontweight='bold', ha='center')
    ax.text(8, 1.1, '• Data Analysis\n• Visualization\n• Automation', 
            fontsize=8, ha='center')
    
    # Connections to memory and tools
    for x in [2, 8]:
        ax.annotate('', xy=(5, 8), xytext=(x, 1.8),
                   arrowprops=dict(arrowstyle='->', color='purple', alpha=0.7))
    
    plt.tight_layout()
    plt.savefig('vm_system_architecture.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_roadblock_solution_mapping():
    """Create diagram showing how each agent addresses specific roadblocks"""
    
    fig, ax = plt.subplots(1, 1, figsize=(14, 10))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis('off')
    
    ax.text(5, 9.5, 'Roadblock → Solution Mapping', 
            fontsize=16, fontweight='bold', ha='center')
    
    # Roadblocks on left, solutions on right
    roadblocks = [
        ('Incomplete Asset Visibility', 8.5),
        ('Overwhelming Volume', 7.5),
        ('Resource Constraints', 6.5),
        ('Siloed Teams', 5.5),
        ('Reactive Mindset', 4.5),
        ('Legacy Systems', 3.5),
        ('Patch Delays', 2.5)
    ]
    
    solutions = [
        ('Asset Discovery Agent\n• Automated discovery\n• Shadow IT detection\n• Real-time inventory', 8.5),
        ('Risk Prioritization Agent\n• Business context scoring\n• False positive reduction\n• Threat correlation', 7.5),
        ('Resource Optimization Agent\n• ROI calculations\n• Automation opportunities\n• Budget optimization', 6.5),
        ('Collaboration Agent\n• Cross-team workflows\n• Stakeholder dashboards\n• SLA management', 5.5),
        ('Strategic Planning Agent\n• Maturity roadmaps\n• Long-term strategy\n• Value demonstration', 4.5),
        ('Legacy Systems Agent\n• Compensating controls\n• Risk mitigation\n• Modernization planning', 3.5),
        ('Patch Management Agent\n• Automated testing\n• Staged deployment\n• Complex orchestration', 2.5)
    ]
    
    # Draw roadblocks
    for roadblock, y in roadblocks:
        roadblock_box = FancyBboxPatch((0.5, y-0.3), 3, 0.6,
                                       boxstyle="round,pad=0.05",
                                       facecolor='lightcoral',
                                       edgecolor='darkred')
        ax.add_patch(roadblock_box)
        ax.text(2, y, roadblock, fontsize=10, fontweight='bold', ha='center', va='center')
    
    # Draw solutions
    for solution, y in solutions:
        solution_box = FancyBboxPatch((6, y-0.3), 3.5, 0.6,
                                      boxstyle="round,pad=0.05",
                                      facecolor='lightgreen',
                                      edgecolor='darkgreen')
        ax.add_patch(solution_box)
        ax.text(7.75, y, solution, fontsize=9, ha='center', va='center')
    
    # Draw arrows
    for _, y in roadblocks:
        ax.annotate('', xy=(6, y), xytext=(3.5, y),
                   arrowprops=dict(arrowstyle='->', color='blue', lw=2))
    
    plt.tight_layout()
    plt.savefig('roadblock_solution_mapping.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_workflow_diagram():
    """Create workflow diagram showing typical system usage"""
    
    fig, ax = plt.subplots(1, 1, figsize=(12, 8))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 8)
    ax.axis('off')
    
    ax.text(5, 7.5, 'Typical Vulnerability Management Workflow', 
            fontsize=14, fontweight='bold', ha='center')
    
    # Workflow steps
    steps = [
        ('1. Asset Discovery', 1, 6, 'lightblue'),
        ('2. Vulnerability Scan', 3, 6, 'orange'),
        ('3. Risk Prioritization', 5, 6, 'yellow'),
        ('4. Resource Planning', 7, 6, 'lightgreen'),
        ('5. Team Coordination', 9, 6, 'pink'),
        ('6. Patch Testing', 2, 4, 'lightcyan'),
        ('7. Deployment', 4, 4, 'lavender'),
        ('8. Monitoring', 6, 4, 'lightgray'),
        ('9. Strategic Review', 8, 4, 'lightcoral')
    ]
    
    for step, x, y, color in steps:
        step_box = FancyBboxPatch((x-0.5, y-0.3), 1, 0.6,
                                  boxstyle="round,pad=0.05",
                                  facecolor=color,
                                  edgecolor='black')
        ax.add_patch(step_box)
        ax.text(x, y, step, fontsize=9, fontweight='bold', ha='center', va='center')
    
    # Workflow arrows
    arrows = [
        ((1, 6), (3, 6)),
        ((3, 6), (5, 6)),
        ((5, 6), (7, 6)),
        ((7, 6), (9, 6)),
        ((9, 6), (2, 4)),
        ((2, 4), (4, 4)),
        ((4, 4), (6, 4)),
        ((6, 4), (8, 4)),
        ((8, 4), (1, 6))  # Feedback loop
    ]
    
    for start, end in arrows:
        if start == (8, 4) and end == (1, 6):  # Feedback loop
            ax.annotate('', xy=end, xytext=start,
                       arrowprops=dict(arrowstyle='->', color='red', lw=2,
                                     connectionstyle="arc3,rad=0.3"))
        else:
            ax.annotate('', xy=end, xytext=start,
                       arrowprops=dict(arrowstyle='->', color='blue', lw=1.5))
    
    # Add continuous improvement annotation
    ax.text(5, 2, 'Continuous Improvement Loop', 
            fontsize=12, fontweight='bold', ha='center', color='red')
    
    plt.tight_layout()
    plt.savefig('vm_workflow_diagram.png', dpi=300, bbox_inches='tight')
    plt.show()

if __name__ == "__main__":
    print("Creating vulnerability management system diagrams...")
    create_architecture_diagram()
    create_roadblock_solution_mapping()
    create_workflow_diagram()
    print("Diagrams saved as PNG files.")
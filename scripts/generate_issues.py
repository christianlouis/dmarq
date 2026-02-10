#!/usr/bin/env python3
"""
Script to generate GitHub issues from DMARQ roadmap documents.

This script parses the roadmap files and creates structured issue templates
that can be imported to GitHub.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class Issue:
    """Represents a GitHub issue."""
    title: str
    body: str
    labels: List[str]
    milestone: str = ""
    assignees: List[str] = None
    
    def __post_init__(self):
        if self.assignees is None:
            self.assignees = []


class RoadmapParser:
    """Parser for DMARQ roadmap documents."""
    
    def __init__(self, roadmap_path: Path):
        self.roadmap_path = roadmap_path
        self.content = roadmap_path.read_text()
        self.issues: List[Issue] = []
        
    def parse_security_sprint(self) -> List[Issue]:
        """Parse the Security Remediation Sprint section."""
        issues = []
        
        # Pattern to match sections like "#### 1. Authentication & Authorization (CRITICAL)"
        section_pattern = r'####\s+(\d+)\.\s+(.+?)\((.+?)\)\s*\n(.*?)(?=####|\n##|\Z)'
        
        for match in re.finditer(section_pattern, self.content, re.DOTALL):
            section_num = match.group(1)
            title = match.group(2).strip()
            priority = match.group(3).strip()
            content = match.group(4).strip()
            
            # Extract checklist items
            checklist_items = re.findall(r'- \[ \] (.+)', content)
            
            # Extract files to fix
            files_section = re.search(r'\*\*Files to Fix\*\*:\s*\n((?:\s*-\s+`.+?`.*\n?)+)', content)
            files = []
            if files_section:
                files = re.findall(r'-\s+`(.+?)`', files_section.group(1))
            
            # Build issue body
            body_parts = [
                f"## Description",
                f"",
                f"Part of the **Security Remediation Sprint** - Priority: **{priority}**",
                f"",
                f"### Tasks",
                ""
            ]
            
            for item in checklist_items:
                body_parts.append(f"- [ ] {item}")
            
            if files:
                body_parts.extend([
                    "",
                    "### Files to Update",
                    ""
                ])
                for file in files:
                    body_parts.append(f"- `{file}`")
            
            body_parts.extend([
                "",
                "### Related Documentation",
                "",
                "- [SECURITY.md](../SECURITY.md)",
                "- [Security Remediation Sprint](../ROADMAP.md#security-remediation-sprint-priority---in-progress)",
                "",
                "---",
                "*This issue was auto-generated from the DMARQ roadmap.*"
            ])
            
            # Determine labels based on priority
            labels = ["security"]
            if "CRITICAL" in priority:
                labels.extend(["priority: critical", "security: critical"])
            elif "HIGH" in priority:
                labels.extend(["priority: high", "security: high"])
            elif "MEDIUM" in priority:
                labels.extend(["priority: medium"])
            
            issue = Issue(
                title=f"[Security Sprint] {title}",
                body="\n".join(body_parts),
                labels=labels,
                milestone="Security Remediation Sprint"
            )
            issues.append(issue)
        
        return issues
    
    def parse_milestone_features(self) -> List[Issue]:
        """Parse milestone features from the roadmap."""
        issues = []
        
        # Pattern to match milestone sections
        milestone_pattern = r'##\s+Milestone\s+(\d+):\s+(.+?)(?:\((.+?)\))?\s*\n(.*?)(?=\n##|\Z)'
        
        for match in re.finditer(milestone_pattern, self.content, re.DOTALL):
            milestone_num = match.group(1)
            milestone_name = match.group(2).strip()
            timeline = match.group(3) or ""
            content = match.group(4).strip()
            
            # Skip completed milestones
            if "COMPLETE ✅" in milestone_name or "✅" in content[:100]:
                continue
            
            # Extract planned features
            features_match = re.search(r'###\s+Planned Features\s*\n((?:- \[ \].+\n?)+)', content, re.MULTILINE)
            security_match = re.search(r'###\s+Security (?:Features|Considerations|Enhancements Needed)\s*\n((?:- \[ \].+\n?)+)', content, re.MULTILINE)
            
            if features_match:
                features = re.findall(r'- \[ \] (.+)', features_match.group(1))
                
                for feature in features:
                    body_parts = [
                        f"## Description",
                        f"",
                        f"Feature for **Milestone {milestone_num}: {milestone_name}**",
                        f"",
                    ]
                    
                    if timeline:
                        body_parts.append(f"**Timeline**: {timeline}")
                        body_parts.append("")
                    
                    body_parts.extend([
                        f"### Feature",
                        f"{feature}",
                        "",
                    ])
                    
                    # Add security considerations if they exist
                    if security_match:
                        security_items = re.findall(r'- \[ \] (.+)', security_match.group(1))
                        if security_items:
                            body_parts.extend([
                                "### Security Considerations",
                                ""
                            ])
                            for item in security_items:
                                body_parts.append(f"- [ ] {item}")
                            body_parts.append("")
                    
                    body_parts.extend([
                        "### Related Documentation",
                        "",
                        f"- [Milestone {milestone_num}](../ROADMAP.md#milestone-{milestone_num}-{milestone_name.lower().replace(' ', '-').replace('&', '').replace('(', '').replace(')', '')})",
                        "",
                        "---",
                        "*This issue was auto-generated from the DMARQ roadmap.*"
                    ])
                    
                    labels = ["enhancement", f"milestone-{milestone_num}"]
                    
                    # Add priority based on milestone
                    if int(milestone_num) <= 5:
                        labels.append("priority: high")
                    elif int(milestone_num) <= 8:
                        labels.append("priority: medium")
                    else:
                        labels.append("priority: low")
                    
                    issue = Issue(
                        title=f"[M{milestone_num}] {feature[:80]}",
                        body="\n".join(body_parts),
                        labels=labels,
                        milestone=f"Milestone {milestone_num}: {milestone_name}"
                    )
                    issues.append(issue)
            
            # Create separate issues for security enhancements
            if security_match and "Security Enhancements Needed" in content:
                security_items = re.findall(r'- \[ \] (.+)', security_match.group(1))
                
                if security_items:
                    body_parts = [
                        f"## Description",
                        f"",
                        f"Security enhancements for **Milestone {milestone_num}: {milestone_name}**",
                        f"",
                        "### Security Tasks",
                        ""
                    ]
                    
                    for item in security_items:
                        body_parts.append(f"- [ ] {item}")
                    
                    body_parts.extend([
                        "",
                        "### Related Documentation",
                        "",
                        f"- [Milestone {milestone_num}](../ROADMAP.md#milestone-{milestone_num}-{milestone_name.lower().replace(' ', '-').replace('&', '').replace('(', '').replace(')', '')})",
                        "- [SECURITY.md](../SECURITY.md)",
                        "",
                        "---",
                        "*This issue was auto-generated from the DMARQ roadmap.*"
                    ])
                    
                    issue = Issue(
                        title=f"[M{milestone_num}] Security Enhancements for {milestone_name}",
                        body="\n".join(body_parts),
                        labels=["security", f"milestone-{milestone_num}", "enhancement"],
                        milestone=f"Milestone {milestone_num}: {milestone_name}"
                    )
                    issues.append(issue)
        
        return issues
    
    def parse_continuous_improvements(self) -> List[Issue]:
        """Parse continuous improvement tasks."""
        issues = []
        
        # Find the Continuous Improvements section
        ci_start = self.content.find('## Continuous Improvements')
        if ci_start == -1:
            return issues
        
        # Find the end at "---" or next "##"
        content_after_ci = self.content[ci_start:]
        
        # Find the first separator (--- line by itself)
        separator_match = re.search(r'\n---\n', content_after_ci)
        next_section_match = re.search(r'\n## [^C]', content_after_ci)  # Next section that doesn't start with 'C'
        
        # Take whichever comes first
        end_pos = len(content_after_ci)
        if separator_match and next_section_match:
            end_pos = min(separator_match.start(), next_section_match.start())
        elif separator_match:
            end_pos = separator_match.start()
        elif next_section_match:
            end_pos = next_section_match.start()
        
        ci_content = content_after_ci[:end_pos]
        
        # Split by ### to get subsections
        subsections = re.split(r'\n###\s+', ci_content)
        
        for subsection in subsections[1:]:  # Skip the first split (the title)
            lines = subsection.split('\n')
            if not lines:
                continue
                
            category = lines[0].strip()
            items = []
            
            for line in lines[1:]:
                match = re.match(r'- \[ \] (.+)', line)
                if match:
                    items.append(match.group(1))
            
            if not items:
                continue
            
            body_parts = [
                f"## Description",
                f"",
                f"Ongoing {category.lower()} tasks to maintain and improve DMARQ.",
                f"",
                "### Tasks",
                ""
            ]
            
            for item in items:
                body_parts.append(f"- [ ] {item}")
            
            body_parts.extend([
                "",
                "### Related Documentation",
                "",
                "- [Continuous Improvements](../ROADMAP.md#continuous-improvements-ongoing)",
                "",
                "---",
                "*This issue was auto-generated from the DMARQ roadmap.*"
            ])
            
            labels = ["maintenance", "continuous-improvement"]
            
            if category.lower() == "security":
                labels.append("security")
            elif category.lower() == "documentation":
                labels.append("documentation")
            elif category.lower() == "code quality":
                labels.append("code-quality")
            
            issue = Issue(
                title=f"[Continuous] {category} Improvements",
                body="\n".join(body_parts),
                labels=labels,
                milestone="Continuous Improvements"
            )
            issues.append(issue)
        
        return issues
    
    def parse_all(self) -> List[Issue]:
        """Parse all issues from the roadmap."""
        print(f"Parsing {self.roadmap_path.name}...")
        
        self.issues.extend(self.parse_security_sprint())
        print(f"  - Found {len(self.issues)} security sprint issues")
        
        milestone_count = len(self.issues)
        self.issues.extend(self.parse_milestone_features())
        print(f"  - Found {len(self.issues) - milestone_count} milestone feature issues")
        
        ci_count = len(self.issues)
        self.issues.extend(self.parse_continuous_improvements())
        print(f"  - Found {len(self.issues) - ci_count} continuous improvement issues")
        
        return self.issues


def save_issues_json(issues: List[Issue], output_path: Path):
    """Save issues to JSON file."""
    issues_data = [asdict(issue) for issue in issues]
    
    with output_path.open('w') as f:
        json.dump(issues_data, f, indent=2)
    
    print(f"\nSaved {len(issues)} issues to {output_path}")


def save_issues_markdown(issues: List[Issue], output_path: Path):
    """Save issues to Markdown file for easy review."""
    with output_path.open('w') as f:
        f.write("# DMARQ Roadmap Issues\n\n")
        f.write(f"Auto-generated from roadmap documents.\n\n")
        f.write(f"**Total Issues**: {len(issues)}\n\n")
        f.write("---\n\n")
        
        # Group by milestone
        by_milestone = {}
        for issue in issues:
            milestone = issue.milestone or "No Milestone"
            if milestone not in by_milestone:
                by_milestone[milestone] = []
            by_milestone[milestone].append(issue)
        
        for milestone, milestone_issues in sorted(by_milestone.items()):
            f.write(f"## {milestone}\n\n")
            f.write(f"**Count**: {len(milestone_issues)}\n\n")
            
            for issue in milestone_issues:
                f.write(f"### {issue.title}\n\n")
                f.write(f"**Labels**: {', '.join(issue.labels)}\n\n")
                f.write("```markdown\n")
                f.write(issue.body)
                f.write("\n```\n\n")
                f.write("---\n\n")
    
    print(f"Saved issues preview to {output_path}")


def save_github_import_script(issues: List[Issue], output_path: Path):
    """Save a bash script to import issues using GitHub CLI."""
    script_lines = [
        "#!/bin/bash",
        "#",
        "# Script to create GitHub issues from DMARQ roadmap",
        "# Requires: GitHub CLI (gh) - https://cli.github.com/",
        "#",
        "# Usage: ./create_issues.sh",
        "#",
        "",
        "set -e",
        "",
        "REPO=\"christianlouis/dmarq\"",
        "",
        "echo \"Creating GitHub issues for DMARQ roadmap...\"",
        "echo \"Repository: $REPO\"",
        "echo \"\"",
        "",
        "# Check if gh is installed",
        "if ! command -v gh &> /dev/null; then",
        "    echo \"Error: GitHub CLI (gh) is not installed.\"",
        "    echo \"Please install it from: https://cli.github.com/\"",
        "    exit 1",
        "fi",
        "",
        "# Check if authenticated",
        "if ! gh auth status &> /dev/null; then",
        "    echo \"Error: Not authenticated with GitHub CLI.\"",
        "    echo \"Please run: gh auth login\"",
        "    exit 1",
        "fi",
        "",
        "ISSUE_COUNT=0",
        ""
    ]
    
    for i, issue in enumerate(issues, 1):
        # Escape special characters in title and body
        title = issue.title.replace('"', '\\"').replace('$', '\\$')
        body = issue.body.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
        labels = ','.join(issue.labels)
        
        script_lines.extend([
            f"# Issue {i}: {issue.title[:50]}...",
            f"echo \"Creating issue {i}/{len(issues)}: {title[:50]}...\"",
            "gh issue create \\",
            f"  --repo \"$REPO\" \\",
            f"  --title \"{title}\" \\",
            f"  --body \"{body}\" \\",
            f"  --label \"{labels}\" || echo \"  Failed to create issue {i}\"",
            "",
            "ISSUE_COUNT=$((ISSUE_COUNT + 1))",
            "sleep 1  # Rate limiting",
            ""
        ])
    
    script_lines.extend([
        "echo \"\"",
        "echo \"Done! Created $ISSUE_COUNT issues.\"",
        "echo \"\"",
        "echo \"Next steps:\"",
        "echo \"1. Review the created issues at: https://github.com/$REPO/issues\"",
        "echo \"2. Create milestones if needed\"",
        "echo \"3. Assign issues to milestones and team members\"",
        "echo \"4. Start working on the Security Remediation Sprint first!\""
    ])
    
    script_content = "\n".join(script_lines)
    output_path.write_text(script_content)
    output_path.chmod(0o755)  # Make executable
    
    print(f"Saved GitHub CLI import script to {output_path}")


def main():
    """Main function."""
    repo_root = Path(__file__).parent.parent
    roadmap_path = repo_root / "ROADMAP.md"
    output_dir = repo_root / "generated_issues"
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 60)
    print("DMARQ Roadmap Issue Generator")
    print("=" * 60)
    print()
    
    if not roadmap_path.exists():
        print(f"Error: Roadmap file not found at {roadmap_path}")
        return 1
    
    # Parse roadmap
    parser = RoadmapParser(roadmap_path)
    issues = parser.parse_all()
    
    print(f"\n{'=' * 60}")
    print(f"Total issues generated: {len(issues)}")
    print(f"{'=' * 60}\n")
    
    # Save outputs
    save_issues_json(issues, output_dir / "issues.json")
    save_issues_markdown(issues, output_dir / "issues_preview.md")
    save_github_import_script(issues, output_dir / "create_issues.sh")
    
    print("\n" + "=" * 60)
    print("Output files created in:", output_dir)
    print("=" * 60)
    print("\nFiles generated:")
    print(f"  1. issues.json - JSON format for programmatic import")
    print(f"  2. issues_preview.md - Human-readable preview")
    print(f"  3. create_issues.sh - Executable script using GitHub CLI")
    print("\nTo create the issues:")
    print(f"  cd {output_dir}")
    print("  ./create_issues.sh")
    print("\nNote: You'll need GitHub CLI (gh) installed and authenticated.")
    print("      Install from: https://cli.github.com/")
    print()
    
    return 0


if __name__ == "__main__":
    exit(main())

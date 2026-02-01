"""
Zerava Security Scanner - Score Calculator

This module calculates security scores based on the findings from various scanners.
The scoring system provides an overall security rating from 0-100.
"""

import logging
from typing import List, Dict, Tuple
from app.models.finding import Finding

logger = logging.getLogger(__name__)


class ScoreCalculator:
    """
    Calculate security scores based on scan findings.
    
    The scoring algorithm:
    1. Starts with a base score of 100
    2. Deducts points based on finding severity
    3. Applies weighted deductions to prevent score inflation
    4. Ensures score stays within 0-100 range
    """
    
    def __init__(self, base_score: int = 100, weights: Dict[str, int] = None):
        """
        Initialize the score calculator.
        
        Args:
            base_score: Starting score (default: 100)
            weights: Severity weights for deductions
        """
        self.base_score = base_score
        self.weights = weights or {
            'Critical': 40,
            'High': 20,
            'Medium': 10,
            'Low': 5,
            'Info': 0
        }
        
        # Maximum deduction per severity to prevent excessive penalties
        self.max_deductions = {
            'Critical': 80,  # Max 80 points from critical issues
            'High': 60,      # Max 60 points from high issues
            'Medium': 40,    # Max 40 points from medium issues
            'Low': 20,       # Max 20 points from low issues
            'Info': 0        # No deduction for info
        }
    
    def calculate_score(self, findings: List[Finding]) -> Tuple[int, Dict[str, any]]:
        """
        Calculate security score from findings.
        
        Args:
            findings: List of Finding objects
        
        Returns:
            Tuple of (score, breakdown_dict)
        """
        if not findings:
            logger.info("No findings, returning perfect score")
            return self.base_score, {
                'base_score': self.base_score,
                'final_score': self.base_score,
                'total_deductions': 0,
                'deductions_by_severity': {},
                'findings_by_severity': {}
            }
        
        score = self.base_score
        deductions_by_severity = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        findings_by_severity = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        # Count findings by severity
        for finding in findings:
            severity = finding.severity
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1
        
        # Calculate deductions with diminishing returns
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = findings_by_severity[severity]
            if count > 0:
                deduction = self._calculate_severity_deduction(severity, count)
                deductions_by_severity[severity] = deduction
                score -= deduction
        
        # Ensure score stays within bounds
        score = max(0, min(self.base_score, score))
        
        total_deductions = sum(deductions_by_severity.values())
        
        breakdown = {
            'base_score': self.base_score,
            'final_score': score,
            'total_deductions': total_deductions,
            'deductions_by_severity': deductions_by_severity,
            'findings_by_severity': findings_by_severity,
            'total_findings': len(findings)
        }
        
        logger.info(f"Calculated security score: {score}/100 "
                   f"({findings_by_severity['Critical']} critical, "
                   f"{findings_by_severity['High']} high, "
                   f"{findings_by_severity['Medium']} medium, "
                   f"{findings_by_severity['Low']} low)")
        
        return score, breakdown
    
    def _calculate_severity_deduction(self, severity: str, count: int) -> int:
        """
        Calculate deduction for a severity level with diminishing returns.
        
        Uses a logarithmic diminishing returns formula to prevent
        score inflation from many similar issues.
        
        Args:
            severity: Severity level
            count: Number of findings at this severity
        
        Returns:
            Total deduction for this severity level
        """
        if count == 0 or severity not in self.weights:
            return 0
        
        base_weight = self.weights[severity]
        max_deduction = self.max_deductions.get(severity, 100)
        
        # Formula: deduction = base_weight * (1 + log2(count))
        # This gives diminishing returns for multiple findings
        import math
        
        if count == 1:
            deduction = base_weight
        else:
            # Diminishing returns: each additional finding is worth less
            # Using logarithmic scale
            deduction = base_weight * (1 + math.log2(count))
        
        # Cap at maximum deduction for this severity
        deduction = min(deduction, max_deduction)
        
        return int(deduction)
    
    def get_score_rating(self, score: int) -> str:
        """
        Get a letter grade or rating for the score.
        
        Args:
            score: Security score (0-100)
        
        Returns:
            Rating string (A+, A, B, C, D, F)
        """
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D+'
        elif score >= 45:
            return 'D'
        elif score >= 40:
            return 'D-'
        else:
            return 'F'
    
    def get_score_description(self, score: int) -> str:
        """
        Get a human-readable description of the score.
        
        Args:
            score: Security score (0-100)
        
        Returns:
            Description string
        """
        if score >= 90:
            return 'Excellent security posture with minimal vulnerabilities'
        elif score >= 80:
            return 'Good security posture with some minor issues'
        elif score >= 70:
            return 'Acceptable security with several issues to address'
        elif score >= 60:
            return 'Moderate security concerns requiring attention'
        elif score >= 50:
            return 'Significant security vulnerabilities present'
        elif score >= 40:
            return 'Poor security posture with critical issues'
        else:
            return 'Severe security vulnerabilities requiring immediate action'
    
    def get_priority_findings(self, findings: List[Finding], limit: int = 5) -> List[Finding]:
        """
        Get the highest priority findings to fix first.
        
        Args:
            findings: List of all findings
            limit: Maximum number of findings to return
        
        Returns:
            List of priority findings
        """
        # Sort by severity weight (highest first)
        sorted_findings = sorted(
            findings,
            key=lambda f: self.weights.get(f.severity, 0),
            reverse=True
        )
        
        return sorted_findings[:limit]
    
    def calculate_improvement_impact(self, findings: List[Finding], 
                                    findings_to_fix: List[Finding]) -> Dict[str, any]:
        """
        Calculate the score improvement if specific findings are fixed.
        
        Args:
            findings: All current findings
            findings_to_fix: Findings that would be fixed
        
        Returns:
            Dictionary with improvement analysis
        """
        # Calculate current score
        current_score, current_breakdown = self.calculate_score(findings)
        
        # Calculate score after fixes
        remaining_findings = [
            f for f in findings 
            if f.id not in [fix.id for fix in findings_to_fix]
        ]
        improved_score, improved_breakdown = self.calculate_score(remaining_findings)
        
        improvement = improved_score - current_score
        
        return {
            'current_score': current_score,
            'improved_score': improved_score,
            'improvement': improvement,
            'improvement_percentage': (improvement / self.base_score) * 100 if improvement > 0 else 0,
            'findings_to_fix': len(findings_to_fix),
            'remaining_findings': len(remaining_findings)
        }
    
    def get_score_trend_analysis(self, scores: List[int]) -> Dict[str, any]:
        """
        Analyze the trend of scores over time.
        
        Args:
            scores: List of historical scores (newest last)
        
        Returns:
            Dictionary with trend analysis
        """
        if len(scores) < 2:
            return {
                'trend': 'insufficient_data',
                'change': 0,
                'change_percentage': 0
            }
        
        # Calculate change from first to last
        first_score = scores[0]
        last_score = scores[-1]
        change = last_score - first_score
        change_percentage = (change / first_score * 100) if first_score > 0 else 0
        
        # Determine trend
        if change > 5:
            trend = 'improving'
        elif change < -5:
            trend = 'declining'
        else:
            trend = 'stable'
        
        # Calculate average
        avg_score = sum(scores) / len(scores)
        
        return {
            'trend': trend,
            'change': change,
            'change_percentage': change_percentage,
            'average_score': avg_score,
            'best_score': max(scores),
            'worst_score': min(scores),
            'total_scans': len(scores)
        }
    
    def generate_recommendations(self, findings: List[Finding], 
                                score: int) -> List[Dict[str, str]]:
        """
        Generate prioritized recommendations based on findings and score.
        
        Args:
            findings: List of findings
            score: Current security score
        
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Count findings by severity
        severity_counts = {
            'Critical': sum(1 for f in findings if f.severity == 'Critical'),
            'High': sum(1 for f in findings if f.severity == 'High'),
            'Medium': sum(1 for f in findings if f.severity == 'Medium'),
            'Low': sum(1 for f in findings if f.severity == 'Low')
        }
        
        # Critical findings
        if severity_counts['Critical'] > 0:
            recommendations.append({
                'priority': 'Critical',
                'title': 'Address Critical Vulnerabilities Immediately',
                'description': f'You have {severity_counts["Critical"]} critical security '
                              f'issue{"s" if severity_counts["Critical"] > 1 else ""} that require immediate attention. '
                              f'These vulnerabilities could lead to complete system compromise.',
                'action': 'Review and fix all critical findings as soon as possible.'
            })
        
        # High findings
        if severity_counts['High'] > 0:
            recommendations.append({
                'priority': 'High',
                'title': 'Fix High Severity Issues',
                'description': f'You have {severity_counts["High"]} high severity '
                              f'issue{"s" if severity_counts["High"] > 1 else ""} that should be addressed soon. '
                              f'These could lead to significant security breaches.',
                'action': 'Plan to fix high severity findings within the next sprint.'
            })
        
        # Medium findings
        if severity_counts['Medium'] > 3:
            recommendations.append({
                'priority': 'Medium',
                'title': 'Reduce Medium Severity Issues',
                'description': f'You have {severity_counts["Medium"]} medium severity issues. '
                              f'While not immediately critical, these weaken your security posture.',
                'action': 'Address medium severity findings in upcoming releases.'
            })
        
        # Low score overall
        if score < 60:
            recommendations.append({
                'priority': 'High',
                'title': 'Comprehensive Security Review Needed',
                'description': f'Your security score of {score}/100 indicates significant security concerns. '
                              f'Consider a comprehensive security audit.',
                'action': 'Engage security experts for a thorough review and remediation plan.'
            })
        
        # General recommendations
        if score < 80:
            recommendations.append({
                'priority': 'Medium',
                'title': 'Implement Security Best Practices',
                'description': 'Review and implement OWASP security best practices for web applications.',
                'action': 'Train development team on secure coding practices.'
            })
        
        return recommendations
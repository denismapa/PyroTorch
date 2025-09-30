#!/usr/bin/env python3
"""
Firewall Audit Script

This script analyzes firewall rules from a CSV file and generates a professional PDF report
containing analysis of unused rules and overly permissive rules.

Date: 2025-09-29
"""

import argparse
import csv
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
)


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Set up logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


def parse_csv(csv_file_path: str, logger: logging.Logger) -> pd.DataFrame:
    """
    Parse the CSV file containing firewall rules.

    Args:
        csv_file_path: Path to the CSV file
        logger: Logger instance

    Returns:
        DataFrame containing the firewall rules

    Raises:
        FileNotFoundError: If CSV file doesn't exist
        ValueError: If CSV file is malformed or missing required columns
    """
    logger.info(f"Parsing CSV file: {csv_file_path}")

    if not Path(csv_file_path).exists():
        raise FileNotFoundError(f"CSV file not found: {csv_file_path}")

    try:
        df = pd.read_csv(csv_file_path)
        logger.info(f"Successfully loaded {len(df)} rules from CSV")

        # Map Palo Alto column names to standard names
        column_mapping = {
            'Name': 'Rule ID',
            'Source Address': 'Source',
            'Destination Address': 'Destination',
            'Service': 'Protocol',
            'Action': 'Action',
            'Created': 'Created Date',
            'Rule Usage Last Hit': 'Rule Usage Last Hit',
            'Rule Usage Hit Count': 'Rule Usage Hit',
            'Source Zone': 'Source Zone',
            'Destination Zone': 'Destination Zone',
            'Application': 'Application',
            'Profile': 'Profile',
            'Tags': 'Tags'
        }

        # Rename columns if they exist
        for old_name, new_name in column_mapping.items():
            if old_name in df.columns:
                df.rename(columns={old_name: new_name}, inplace=True)
                logger.info(f"Mapped column '{old_name}' to '{new_name}'")

        # Validate required columns
        required_columns = ['Rule ID', 'Source', 'Destination', 'Protocol', 'Action', 'Created Date']
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")

        # Add Port column if not present (Palo Alto uses Service instead)
        if 'Port' not in df.columns:
            df['Port'] = df['Protocol']  # Use Protocol as Port fallback
            logger.info("Created 'Port' column from 'Protocol'")

        # Convert date columns to datetime
        df['Created Date'] = pd.to_datetime(df['Created Date'], errors='coerce')

        # Handle optional date columns
        if 'Last Used Date' in df.columns:
            df['Last Used Date'] = pd.to_datetime(df['Last Used Date'], errors='coerce')
        else:
            logger.warning("'Last Used Date' column not found, creating empty column")
            df['Last Used Date'] = pd.NaT

        if 'Rule Usage Last Hit' in df.columns:
            df['Rule Usage Last Hit'] = pd.to_datetime(df['Rule Usage Last Hit'], errors='coerce')
            logger.info("Found 'Rule Usage Last Hit' column")
        else:
            logger.info("'Rule Usage Last Hit' column not found, creating empty column")
            df['Rule Usage Last Hit'] = pd.NaT

        # Handle optional numeric columns
        if 'Rule Usage Hit' in df.columns:
            df['Rule Usage Hit'] = pd.to_numeric(df['Rule Usage Hit'], errors='coerce')
            logger.info("Found 'Rule Usage Hit' column")
        else:
            logger.info("'Rule Usage Hit' column not found, creating empty column")
            df['Rule Usage Hit'] = pd.NaT

        # Handle optional string columns
        optional_string_columns = ['Source Zone', 'Destination Zone', 'Application', 'Profile', 'Tags']
        for col in optional_string_columns:
            if col in df.columns:
                logger.info(f"Found '{col}' column")
            else:
                logger.info(f"'{col}' column not found, creating empty column")
                df[col] = ""

        logger.info("CSV parsing completed successfully")
        return df

    except pd.errors.EmptyDataError:
        raise ValueError("CSV file is empty")
    except pd.errors.ParserError as e:
        raise ValueError(f"Error parsing CSV file: {e}")
    except Exception as e:
        raise ValueError(f"Unexpected error reading CSV file: {e}")


def find_unused_rules(df: pd.DataFrame, days_threshold: int = 90, logger: logging.Logger = None) -> pd.DataFrame:
    """
    Find unused firewall rules based on last used date.

    Rules are considered unused if:
    - Rule Usage Last Hit is null/empty or older than threshold (preferred)
    - If Rule Usage Last Hit is not available, use Last Used Date
    - If both are null/empty, rule is considered unused
    - Action is Allow/Permit (Deny rules are excluded)

    Args:
        df: DataFrame containing firewall rules
        days_threshold: Number of days to consider a rule as unused (default: 90)
        logger: Logger instance

    Returns:
        DataFrame containing unused rules with additional fields
    """
    if logger:
        logger.info(f"Finding unused rules (threshold: {days_threshold} days)")

    cutoff_date = datetime.now() - timedelta(days=days_threshold)

    # Determine primary date field to use
    has_rule_usage_last_hit = 'Rule Usage Last Hit' in df.columns and not df['Rule Usage Last Hit'].isna().all()
    has_last_used_date = 'Last Used Date' in df.columns and not df['Last Used Date'].isna().all()

    if has_rule_usage_last_hit:
        if logger:
            logger.info("Using 'Rule Usage Last Hit' as primary date field for unused rules analysis")
        primary_date_field = 'Rule Usage Last Hit'
        fallback_date_field = 'Last Used Date' if has_last_used_date else None
    elif has_last_used_date:
        if logger:
            logger.info("Using 'Last Used Date' as primary date field for unused rules analysis")
        primary_date_field = 'Last Used Date'
        fallback_date_field = None
    else:
        if logger:
            logger.warning("No valid date fields found, considering all rules as unused")
        primary_date_field = None
        fallback_date_field = None

    # Create unused mask
    if primary_date_field:
        unused_mask = (
            df[primary_date_field].isna() |
            (df[primary_date_field] < cutoff_date)
        )

        # If we have a fallback field, use it when primary is null
        if fallback_date_field:
            primary_null_mask = df[primary_date_field].isna()
            fallback_valid_mask = ~df[fallback_date_field].isna()
            fallback_unused_mask = (df[fallback_date_field] < cutoff_date)

            # For rules where primary is null but fallback exists, use fallback logic
            unused_mask = unused_mask | (primary_null_mask & fallback_valid_mask & fallback_unused_mask)
    else:
        # No date fields available, all rules considered unused
        unused_mask = pd.Series([True] * len(df), index=df.index)

    # Filter to only include Allow/Permit rules
    action_is_allow = df['Action'].str.upper().isin(['ALLOW', 'PERMIT'])
    unused_mask = unused_mask & action_is_allow

    # Select columns for output, including new optional fields
    output_columns = ['Rule ID']

    # Add Tags after Rule ID
    if 'Tags' in df.columns:
        output_columns.append('Tags')

    # Add Source
    output_columns.append('Source')

    # Add Source Zone after Source
    if 'Source Zone' in df.columns:
        output_columns.append('Source Zone')

    # Add Destination
    output_columns.append('Destination')

    # Add Destination Zone after Destination
    if 'Destination Zone' in df.columns:
        output_columns.append('Destination Zone')

    # Add Protocol after Destination Zone
    output_columns.append('Protocol')

    # Add Application
    if 'Application' in df.columns:
        output_columns.append('Application')

    # Add Profile
    if 'Profile' in df.columns:
        output_columns.append('Profile')

    # Add Action
    output_columns.append('Action')

    # Add Created Date second to last
    output_columns.append('Created Date')

    # Add primary date field last
    if primary_date_field and primary_date_field in df.columns:
        output_columns.append(primary_date_field)

    unused_rules = df[unused_mask][output_columns].copy()

    # Add row number column at the beginning
    unused_rules.insert(0, '#', range(1, len(unused_rules) + 1))

    if logger:
        logger.info(f"Found {len(unused_rules)} unused rules")

    return unused_rules


def find_zero_hit_rules(df: pd.DataFrame, logger: logging.Logger = None) -> pd.DataFrame:
    """
    Find firewall rules with zero hits (never used).

    Rules are considered zero-hit if:
    - Rule Usage Hit Count is 0 or null
    - Action is Allow/Permit (Deny rules are excluded)

    Args:
        df: DataFrame containing firewall rules
        logger: Logger instance

    Returns:
        DataFrame containing zero-hit rules
    """
    if logger:
        logger.info("Finding rules with zero hits")

    # Check if Rule Usage Hit column exists
    if 'Rule Usage Hit' not in df.columns or df['Rule Usage Hit'].isna().all():
        if logger:
            logger.warning("'Rule Usage Hit' column not found or empty, no zero-hit analysis possible")
        return pd.DataFrame()

    # Create zero-hit mask
    zero_hit_mask = (df['Rule Usage Hit'].isna()) | (df['Rule Usage Hit'] == 0)

    # Filter to only include Allow/Permit rules
    action_is_allow = df['Action'].str.upper().isin(['ALLOW', 'PERMIT'])
    zero_hit_mask = zero_hit_mask & action_is_allow

    # Select columns for output
    output_columns = ['Rule ID']

    # Add Tags after Rule ID
    if 'Tags' in df.columns:
        output_columns.append('Tags')

    # Add Source
    output_columns.append('Source')

    # Add Source Zone after Source
    if 'Source Zone' in df.columns:
        output_columns.append('Source Zone')

    # Add Destination
    output_columns.append('Destination')

    # Add Destination Zone after Destination
    if 'Destination Zone' in df.columns:
        output_columns.append('Destination Zone')

    # Add Protocol after Destination Zone
    output_columns.append('Protocol')

    # Add Application
    if 'Application' in df.columns:
        output_columns.append('Application')

    # Add Profile
    if 'Profile' in df.columns:
        output_columns.append('Profile')

    # Add Action
    output_columns.append('Action')

    # Add Created Date second to last
    output_columns.append('Created Date')

    # Add Rule Usage Hit last
    if 'Rule Usage Hit' in df.columns:
        output_columns.append('Rule Usage Hit')

    zero_hit_rules = df[zero_hit_mask][output_columns].copy()

    # Add row number column at the beginning
    zero_hit_rules.insert(0, '#', range(1, len(zero_hit_rules) + 1))

    if logger:
        logger.info(f"Found {len(zero_hit_rules)} rules with zero hits")

    return zero_hit_rules


def find_overly_permissive_rules(df: pd.DataFrame, logger: logging.Logger = None) -> pd.DataFrame:
    """
    Find overly permissive firewall rules.

    Rules are considered overly permissive if:
    - Source is ANY or 0.0.0.0/0
    - Destination is ANY or 0.0.0.0/0
    - Action is Allow/Permit

    Args:
        df: DataFrame containing firewall rules
        logger: Logger instance

    Returns:
        DataFrame containing overly permissive rules
    """
    if logger:
        logger.info("Finding overly permissive rules")

    # Define permissive source/destination patterns
    permissive_patterns = ['ANY', '0.0.0.0/0', 'any', '0.0.0.0']

    # Check for source being any
    source_is_any = df['Source'].str.lower().isin(['any'])

    # Check for destination being any
    dest_is_any = df['Destination'].str.lower().isin(['any'])

    # Check for allow action (case insensitive)
    action_is_allow = df['Action'].str.upper().isin(['ALLOW', 'PERMIT'])

    # Find rules that are overly permissive
    permissive_mask = source_is_any & dest_is_any & action_is_allow

    # Select columns for output, including new optional fields
    output_columns = ['Rule ID']

    # Add Tags after Rule ID
    if 'Tags' in df.columns:
        output_columns.append('Tags')

    # Add Source
    output_columns.append('Source')

    # Add Source Zone after Source
    if 'Source Zone' in df.columns:
        output_columns.append('Source Zone')

    # Add Destination
    output_columns.append('Destination')

    # Add Destination Zone after Destination
    if 'Destination Zone' in df.columns:
        output_columns.append('Destination Zone')

    # Add Protocol after Destination Zone
    output_columns.extend(['Protocol', 'Port'])

    # Add Application
    if 'Application' in df.columns:
        output_columns.append('Application')

    # Add Profile
    if 'Profile' in df.columns:
        output_columns.append('Profile')

    # Add Action
    output_columns.append('Action')

    # Add Rule Usage Hit Count
    if 'Rule Usage Hit' in df.columns:
        output_columns.append('Rule Usage Hit')

    permissive_rules = df[permissive_mask][output_columns].copy()

    # Add row number column at the beginning
    permissive_rules.insert(0, '#', range(1, len(permissive_rules) + 1))

    if logger:
        logger.info(f"Found {len(permissive_rules)} overly permissive rules")

    return permissive_rules


def find_high_usage_rules(df: pd.DataFrame, hit_threshold: int = 1000, logger: logging.Logger = None) -> pd.DataFrame:
    """
    Find high usage firewall rules based on hit count.

    Args:
        df: DataFrame containing firewall rules
        hit_threshold: Minimum hit count to consider a rule as high usage (default: 1000)
        logger: Logger instance

    Returns:
        DataFrame containing high usage rules
    """
    if logger:
        logger.info(f"Finding high usage rules (threshold: {hit_threshold} hits)")

    # Check if Rule Usage Hit column exists and has data
    if 'Rule Usage Hit' not in df.columns or df['Rule Usage Hit'].isna().all():
        if logger:
            logger.warning("'Rule Usage Hit' column not found or empty, no high usage analysis possible")
        return pd.DataFrame()

    # Find rules with hit count above threshold
    high_usage_mask = (
        ~df['Rule Usage Hit'].isna() &
        (df['Rule Usage Hit'] >= hit_threshold)
    )

    # Select columns for output
    output_columns = ['Rule ID']

    # Add Tags after Rule ID
    if 'Tags' in df.columns:
        output_columns.append('Tags')

    # Add Source
    output_columns.append('Source')

    # Add Source Zone after Source
    if 'Source Zone' in df.columns:
        output_columns.append('Source Zone')

    # Add Destination
    output_columns.append('Destination')

    # Add Destination Zone after Destination
    if 'Destination Zone' in df.columns:
        output_columns.append('Destination Zone')

    # Add Protocol after Destination Zone
    output_columns.append('Protocol')

    # Add Application
    if 'Application' in df.columns:
        output_columns.append('Application')

    # Add Profile
    if 'Profile' in df.columns:
        output_columns.append('Profile')

    # Add Rule Usage Hit
    output_columns.append('Rule Usage Hit')

    # Add Rule Usage Last Hit last
    if 'Rule Usage Last Hit' in df.columns:
        output_columns.append('Rule Usage Last Hit')

    high_usage_rules = df[high_usage_mask][output_columns].copy()

    # Sort by hit count descending
    if len(high_usage_rules) > 0:
        high_usage_rules = high_usage_rules.sort_values('Rule Usage Hit', ascending=False)

    # Add row number column at the beginning (after sorting)
    high_usage_rules.insert(0, '#', range(1, len(high_usage_rules) + 1))

    if logger:
        logger.info(f"Found {len(high_usage_rules)} high usage rules")

    return high_usage_rules


def analyze_services(df: pd.DataFrame, logger: logging.Logger = None) -> pd.DataFrame:
    """
    Analyze unique services/protocols used in firewall rules.

    Args:
        df: DataFrame containing firewall rules
        logger: Logger instance

    Returns:
        DataFrame containing unique services with Name, Application, Service/Protocol, and Action columns
        sorted by Action then alphabetically
    """
    if logger:
        logger.info("Analyzing services/protocols")

    required_cols = ['Rule ID', 'Protocol', 'Action', 'Application']
    missing_cols = [col for col in required_cols if col not in df.columns]

    if missing_cols:
        if logger:
            logger.warning(f"Missing columns: {missing_cols}")
        return pd.DataFrame()

    # Select relevant columns and get unique combinations
    services_df = df[['Rule ID', 'Application', 'Protocol', 'Action']].copy()

    # Drop duplicates to get unique combinations
    services_df = services_df.drop_duplicates().reset_index(drop=True)

    # Rename columns for clarity
    services_df = services_df.rename(columns={
        'Rule ID': 'Name',
        'Protocol': 'Service/Protocol'
    })

    # Sort by Action first, then by Application, then by Service/Protocol (all alphabetically)
    services_df = services_df.sort_values(
        by=['Action', 'Application', 'Service/Protocol'],
        ascending=[True, True, True]
    ).reset_index(drop=True)

    if logger:
        logger.info(f"Found {len(services_df)} unique service/protocol combinations")

    return services_df


def analyze_zones(df: pd.DataFrame, logger: logging.Logger = None) -> pd.DataFrame:
    """
    Analyze firewall rules by destination zone.

    Args:
        df: DataFrame containing firewall rules
        logger: Logger instance

    Returns:
        DataFrame containing zone analysis summary
    """
    if logger:
        logger.info("Analyzing rules by destination zone")

    # Check if Destination Zone column exists
    if 'Destination Zone' not in df.columns or df['Destination Zone'].isna().all():
        if logger:
            logger.warning("'Destination Zone' column not found or empty, no zone analysis possible")
        return pd.DataFrame()

    # Group by destination zone and calculate statistics
    zone_stats = df.groupby('Destination Zone').agg({
        'Rule ID': 'count',
        'Action': lambda x: (x.str.upper() == 'PERMIT').sum(),
        'Rule Usage Hit': lambda x: x.sum() if not x.isna().all() else 0
    }).reset_index()

    zone_stats.columns = ['Destination Zone', 'Total Rules', 'Permit Rules', 'Total Hits']
    zone_stats['Deny Rules'] = zone_stats['Total Rules'] - zone_stats['Permit Rules']

    # Reorder columns: move Deny Rules next to Permit Rules, Total Hits to last
    zone_stats = zone_stats[['Destination Zone', 'Total Rules', 'Permit Rules', 'Deny Rules', 'Total Hits']]

    # Sort by total rules descending
    zone_stats = zone_stats.sort_values('Total Rules', ascending=False)

    if logger:
        logger.info(f"Analyzed {len(zone_stats)} destination zones")

    return zone_stats


def generate_pdf_report(
    output_path: str,
    total_rules: int,
    unused_rules: pd.DataFrame,
    zero_hit_rules: pd.DataFrame,
    permissive_rules: pd.DataFrame,
    high_usage_rules: pd.DataFrame,
    services_analysis: pd.DataFrame,
    zone_stats: pd.DataFrame,
    firewall_name: str,
    logger: logging.Logger
) -> None:
    """
    Generate a professional PDF report with firewall audit results.

    Args:
        output_path: Path for the output PDF file
        total_rules: Total number of rules analyzed
        unused_rules: DataFrame containing unused rules
        zero_hit_rules: DataFrame containing zero-hit rules
        permissive_rules: DataFrame containing overly permissive rules
        high_usage_rules: DataFrame containing high usage rules
        zone_stats: DataFrame containing zone analysis
        firewall_name: Name of the firewall being audited
        logger: Logger instance
    """
    logger.info(f"Generating PDF report: {output_path}")

    try:
        # Create PDF document in landscape mode
        from reportlab.lib.pagesizes import landscape
        page_size = landscape(A4)
        doc = SimpleDocTemplate(output_path, pagesize=page_size)
        story = []

        # Available width for content (accounting for margins)
        available_width = page_size[0] - 2*inch

        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        heading_style = styles['Heading2']
        normal_style = styles['Normal']
        small_style = ParagraphStyle(
            'SmallStyle',
            parent=styles['Normal'],
            fontSize=6,
            leading=8
        )
        tiny_style = ParagraphStyle(
            'TinyStyle',
            parent=styles['Normal'],
            fontSize=5,
            leading=6
        )

        # Title
        story.append(Paragraph("Firewall Audit Report", title_style))
        story.append(Spacer(1, 20))

        # Firewall name and report date
        story.append(Paragraph(f"<b>Firewall:</b> {firewall_name}", normal_style))
        story.append(Spacer(1, 10))
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"<b>Report Generated:</b> {report_date}", normal_style))
        story.append(Spacer(1, 20))

        # Table of Contents
        story.append(Paragraph("Table of Contents", heading_style))
        story.append(Spacer(1, 12))

        toc_data = [
            ['Section', 'Description'],
            ['1', '<link href="#executive_summary" color="blue">Executive Summary</link>'],
            ['2', '<link href="#unused_rules" color="blue">Unused Rules Analysis</link>'],
            ['3', '<link href="#zero_hit_rules" color="blue">Zero-Hit Rules Analysis</link>'],
            ['4', '<link href="#permissive_rules" color="blue">Overly Permissive Rules Analysis</link>'],
            ['5', '<link href="#high_usage_rules" color="blue">High Usage Rules Analysis</link>'],
            ['6', '<link href="#services_analysis" color="blue">Services, Ports & Protocols</link>']
        ]

        toc_table_data = [[Paragraph(str(cell), normal_style) for cell in row] for row in toc_data]
        toc_table = Table(toc_table_data, colWidths=[1*inch, 5*inch])
        toc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(toc_table)
        story.append(PageBreak())

        # Section 1: Summary
        story.append(Paragraph('<a name="executive_summary"/>Executive Summary', heading_style))
        story.append(Spacer(1, 12))

        summary_raw_data = [
            ['Metric', 'Count', 'Description'],
            ['Firewall Name', firewall_name, 'Name of the firewall being audited'],
            ['Total Rules Analyzed', str(total_rules), 'Total number of firewall rules in the configuration'],
            ['Unused Rules', str(len(unused_rules)), 'Rules not used in the last 90 days'],
            ['Zero-Hit Rules', str(len(zero_hit_rules)), 'Rules with zero traffic hits recorded'],
            ['Overly Permissive Rules', str(len(permissive_rules)), 'Rules with any source, destination, or service'],
            ['High Usage Rules', str(len(high_usage_rules)), 'Rules exceeding the high usage threshold (1000+ hits)'],
            ['Destination Zones', str(len(zone_stats)) if len(zone_stats) > 0 else 'N/A', 'Number of unique destination zones configured'],
            ['Rules Requiring Review', str(len(unused_rules) + len(zero_hit_rules) + len(permissive_rules)), 'Total rules needing attention (unused + zero-hit + permissive)']
        ]

        # Convert to Paragraph objects for proper text wrapping
        summary_data = []
        for row in summary_raw_data:
            summary_data.append([Paragraph(str(cell), normal_style) for cell in row])

        summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch, 3.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (1, -1), 'CENTER'),  # Center align first two columns
            ('ALIGN', (2, 0), (2, -1), 'LEFT'),    # Left align Description column
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        # Section 2: Unused Rules
        story.append(PageBreak())
        story.append(Paragraph('<a name="unused_rules"/>Unused Rules Analysis', heading_style))
        story.append(Spacer(1, 12))

        if len(unused_rules) > 0:
            story.append(Paragraph(
                f"The following {len(unused_rules)} rules have not been used in the last 90 days "
                "or have no usage data. Consider reviewing these rules for potential removal.",
                normal_style
            ))
            story.append(Spacer(1, 12))

            # Convert DataFrame to list for table - dynamically build based on available columns
            if len(unused_rules) > 0:
                headers = list(unused_rules.columns)
                # Use smaller font for tables with many columns
                if len(headers) > 8:
                    cell_style = tiny_style
                elif len(headers) > 7:
                    cell_style = small_style
                else:
                    cell_style = styles['Normal']
                unused_data = [[Paragraph(str(h), cell_style) for h in headers]]

                for _, row in unused_rules.iterrows():
                    row_data = []
                    for col in headers:
                        if col in ['Created Date', 'Rule Usage Last Hit'] and pd.notna(row[col]):
                            cell_text = row[col].strftime('%Y-%m-%d')
                        else:
                            cell_text = str(row[col]) if pd.notna(row[col]) else 'N/A'
                            # Truncate very long text to prevent rendering issues
                            if len(cell_text) > 200:
                                cell_text = cell_text[:197] + '...'
                        row_data.append(Paragraph(cell_text, cell_style))
                    unused_data.append(row_data)

                # Dynamic column widths based on number of columns and content
                col_width = available_width / len(headers)
                unused_table = Table(unused_data, colWidths=[col_width] * len(headers), repeatRows=1)
            else:
                unused_data = [['No unused rules found']]
                unused_table = Table(unused_data, colWidths=[6*inch])
            # Adjust font size based on number of columns
            if len(headers) > 8:
                header_font_size = 6
                cell_font_size = 5
            elif len(headers) > 7:
                header_font_size = 8
                cell_font_size = 6
            else:
                header_font_size = 10
                cell_font_size = 8

            unused_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), header_font_size),
                ('FONTSIZE', (0, 1), (-1, -1), cell_font_size),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))

            story.append(unused_table)
        else:
            story.append(Paragraph("No unused rules found.", normal_style))

        story.append(PageBreak())

        # Section 3: Zero-Hit Rules
        story.append(Paragraph('<a name="zero_hit_rules"/>Zero-Hit Rules Analysis', heading_style))
        story.append(Spacer(1, 12))

        if len(zero_hit_rules) > 0:
            story.append(Paragraph(
                f"The following {len(zero_hit_rules)} rules have never been used (zero hits). "
                "These rules have no recorded usage and are strong candidates for removal.",
                normal_style
            ))
            story.append(Spacer(1, 12))

            # Convert DataFrame to list for table
            headers = list(zero_hit_rules.columns)
            # Use smaller font for tables with many columns
            if len(headers) > 8:
                cell_style = tiny_style
            elif len(headers) > 7:
                cell_style = small_style
            else:
                cell_style = styles['Normal']
            zero_hit_data = [[Paragraph(str(h), cell_style) for h in headers]]

            for _, row in zero_hit_rules.iterrows():
                row_data = []
                for col in headers:
                    if col in ['Created Date'] and pd.notna(row[col]):
                        cell_text = row[col].strftime('%Y-%m-%d')
                    else:
                        cell_text = str(row[col]) if pd.notna(row[col]) else 'N/A'
                        # Truncate very long text to prevent rendering issues
                        if len(cell_text) > 200:
                            cell_text = cell_text[:197] + '...'
                    row_data.append(Paragraph(cell_text, cell_style))
                zero_hit_data.append(row_data)

            # Dynamic column widths
            col_width = available_width / len(headers)
            zero_hit_table = Table(zero_hit_data, colWidths=[col_width] * len(headers), repeatRows=1)

            # Adjust font size based on number of columns
            if len(headers) > 8:
                header_font_size = 6
                cell_font_size = 5
            elif len(headers) > 7:
                header_font_size = 8
                cell_font_size = 6
            else:
                header_font_size = 10
                cell_font_size = 8

            zero_hit_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), header_font_size),
                ('FONTSIZE', (0, 1), (-1, -1), cell_font_size),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightyellow),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))

            story.append(zero_hit_table)
        else:
            story.append(Paragraph("No zero-hit rules found.", normal_style))

        story.append(PageBreak())

        # Section 4: Overly Permissive Rules
        story.append(Paragraph('<a name="permissive_rules"/>Overly Permissive Rules Analysis', heading_style))
        story.append(Spacer(1, 12))

        if len(permissive_rules) > 0:
            story.append(Paragraph(
                f"The following {len(permissive_rules)} rules are overly permissive "
                "(source and destination are ANY/0.0.0.0/0 with Permit action). "
                "Review these rules for security compliance.",
                normal_style
            ))
            story.append(Spacer(1, 12))

            # Convert DataFrame to list for table - dynamically build based on available columns
            headers = list(permissive_rules.columns)
            # Use smaller font for tables with many columns
            if len(headers) > 8:
                cell_style = tiny_style
            elif len(headers) > 7:
                cell_style = small_style
            else:
                cell_style = styles['Normal']
            permissive_data = [[Paragraph(str(h), cell_style) for h in headers]]

            for _, row in permissive_rules.iterrows():
                row_data = []
                for col in headers:
                    cell_text = str(row[col]) if pd.notna(row[col]) else 'N/A'
                    # Truncate very long text to prevent rendering issues
                    if len(cell_text) > 200:
                        cell_text = cell_text[:197] + '...'
                    row_data.append(Paragraph(cell_text, cell_style))
                permissive_data.append(row_data)

            # Dynamic column widths based on number of columns and content
            col_width = available_width / len(headers)
            permissive_table = Table(permissive_data, colWidths=[col_width] * len(headers), repeatRows=1)

            # Adjust font size based on number of columns
            if len(headers) > 8:
                header_font_size = 6
                cell_font_size = 5
            elif len(headers) > 7:
                header_font_size = 8
                cell_font_size = 6
            else:
                header_font_size = 10
                cell_font_size = 8

            permissive_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), header_font_size),
                ('FONTSIZE', (0, 1), (-1, -1), cell_font_size),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))

            story.append(permissive_table)
        else:
            story.append(Paragraph("No overly permissive rules found.", normal_style))

        story.append(PageBreak())

        # Section 5: High Usage Rules
        story.append(Paragraph('<a name="high_usage_rules"/>High Usage Rules Analysis', heading_style))
        story.append(Spacer(1, 12))

        if len(high_usage_rules) > 0:
            story.append(Paragraph(
                f"The following {len(high_usage_rules)} rules have high usage activity. "
                "These rules are frequently accessed and should be carefully monitored.",
                normal_style
            ))
            story.append(Spacer(1, 12))

            # Convert DataFrame to list for table
            headers = list(high_usage_rules.columns)
            # Use smaller font for tables with many columns
            if len(headers) > 8:
                cell_style = tiny_style
            elif len(headers) > 7:
                cell_style = small_style
            else:
                cell_style = styles['Normal']
            high_usage_data = [[Paragraph(str(h), cell_style) for h in headers]]

            for _, row in high_usage_rules.iterrows():
                row_data = []
                for col in headers:
                    if col == 'Rule Usage Last Hit' and pd.notna(row[col]):
                        cell_text = row[col].strftime('%Y-%m-%d')
                    else:
                        cell_text = str(row[col]) if pd.notna(row[col]) else 'N/A'
                        # Truncate very long text to prevent rendering issues
                        if len(cell_text) > 200:
                            cell_text = cell_text[:197] + '...'
                    row_data.append(Paragraph(cell_text, cell_style))
                high_usage_data.append(row_data)

            # Dynamic column widths
            col_width = available_width / len(headers)
            high_usage_table = Table(high_usage_data, colWidths=[col_width] * len(headers), repeatRows=1)

            # Adjust font size based on number of columns
            if len(headers) > 8:
                header_font_size = 6
                cell_font_size = 5
            elif len(headers) > 7:
                header_font_size = 8
                cell_font_size = 6
            else:
                header_font_size = 10
                cell_font_size = 8

            high_usage_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), header_font_size),
                ('FONTSIZE', (0, 1), (-1, -1), cell_font_size),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))

            story.append(high_usage_table)
        else:
            story.append(Paragraph("No high usage rules found or usage data not available.", normal_style))

        story.append(PageBreak())

        # Section 6: Services, Ports & Protocols
        story.append(Paragraph('<a name="services_analysis"/>Services, Ports & Protocols', heading_style))
        story.append(Spacer(1, 12))

        if len(services_analysis) > 0:
            story.append(Paragraph(
                f"Analysis of {len(services_analysis)} unique service/protocol combinations used across firewall rules. "
                "This shows the distribution of services, ports, and protocols with their associated actions.",
                normal_style
            ))
            story.append(Spacer(1, 12))

            # Convert DataFrame to list for table
            service_headers = list(services_analysis.columns)
            service_data = [[Paragraph(str(h), styles['Normal']) for h in service_headers]]

            for _, row in services_analysis.iterrows():
                row_data = []
                for col in service_headers:
                    cell_text = str(row[col]) if pd.notna(row[col]) else 'N/A'
                    row_data.append(Paragraph(cell_text, styles['Normal']))
                service_data.append(row_data)

            # Dynamic column widths
            col_width = available_width / len(service_headers)
            service_table = Table(service_data, colWidths=[col_width] * len(service_headers), repeatRows=1)

            service_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightcyan),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(service_table)
        else:
            story.append(Paragraph("No services/protocols data available.", normal_style))


        # Build PDF
        doc.build(story)
        logger.info(f"PDF report generated successfully: {output_path}")

    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise


def main():
    """Main function to orchestrate the firewall audit process."""
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Analyze firewall rules and generate a PDF audit report"
    )
    parser.add_argument(
        "input_csv",
        help="Path to the input CSV file containing firewall rules"
    )
    parser.add_argument(
        "output_pdf",
        help="Path for the output PDF report"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set the logging level (default: INFO)"
    )
    parser.add_argument(
        "--unused-days",
        type=int,
        default=90,
        help="Number of days to consider a rule as unused (default: 90)"
    )
    parser.add_argument(
        "--high-usage-threshold",
        type=int,
        default=1000,
        help="Minimum hit count to consider a rule as high usage (default: 1000)"
    )
    parser.add_argument(
        "--firewall-name",
        type=str,
        default=None,
        help="Name of the firewall (default: derived from CSV filename)"
    )

    args = parser.parse_args()

    # Set up logging
    logger = setup_logging(args.log_level)

    try:
        logger.info("Starting firewall audit process")

        # Determine firewall name
        if args.firewall_name:
            firewall_name = args.firewall_name
        else:
            # Extract firewall name from CSV filename
            from pathlib import Path
            firewall_name = Path(args.input_csv).stem

        # Parse CSV file
        df = parse_csv(args.input_csv, logger)

        # Analyze rules
        unused_rules = find_unused_rules(df, args.unused_days, logger)
        zero_hit_rules = find_zero_hit_rules(df, logger)
        permissive_rules = find_overly_permissive_rules(df, logger)
        high_usage_rules = find_high_usage_rules(df, args.high_usage_threshold, logger)
        services_analysis = analyze_services(df, logger)
        zone_stats = analyze_zones(df, logger)

        # Generate output filename with firewall name and timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output_filename = f"{firewall_name}_{timestamp}.pdf"

        # If output_pdf path has a directory, use it; otherwise use current directory
        from pathlib import Path
        output_dir = Path(args.output_pdf).parent
        if str(output_dir) != '.':
            output_path = output_dir / output_filename
        else:
            output_path = output_filename

        # Generate PDF report
        generate_pdf_report(
            str(output_path),
            len(df),
            unused_rules,
            zero_hit_rules,
            permissive_rules,
            high_usage_rules,
            services_analysis,
            zone_stats,
            firewall_name,
            logger
        )

        logger.info("Firewall audit completed successfully")
        print(f"\nAudit Summary:")
        print(f"  Total rules analyzed: {len(df)}")
        print(f"  Unused rules found: {len(unused_rules)}")
        print(f"  Zero-hit rules found: {len(zero_hit_rules)}")
        print(f"  Overly permissive rules found: {len(permissive_rules)}")
        print(f"  High usage rules found: {len(high_usage_rules)}")
        print(f"  Destination zones analyzed: {len(zone_stats) if len(zone_stats) > 0 else 'N/A'}")
        print(f"  Report saved to: {output_path}")

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Data validation error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
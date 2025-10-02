// utils/exportUtils.js
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const ExcelJS = require('exceljs');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');

/**
 * Export data to CSV or Excel format
 * @param {Object} options - Export configuration options
 * @param {Array} options.data - Array of objects to export
 * @param {Array} options.columns - Column definitions [{ key: 'id', header: 'ID', width: 10 }]
 * @param {Object} options.res - Express response object
 * @param {string} options.format - Export format ('csv' or 'excel')
 * @param {string} options.fileName - Base filename (without extension)
 * @param {Object} options.excelOptions - Optional Excel-specific options
 * @param {string} options.excelOptions.sheetName - Excel sheet name (default: 'Sheet1')
 * @param {boolean} options.excelOptions.autoFilter - Enable auto filter (default: true)
 * @param {boolean} options.excelOptions.freezeHeader - Freeze header row (default: true)
 * @param {boolean} options.excelOptions.alternateRows - Alternate row colors (default: true)
 * @param {Function} options.excelOptions.cellFormatter - Custom cell formatting function
 * @param {Object} options.metadata - Optional metadata for the export
 * @returns {Promise<void>}
 */
const exportData = async ({
    data,
    columns,
    res,
    format = 'csv',
    fileName = 'export',
    excelOptions = {},
    metadata = {}
}) => {
    try {
        // Validate inputs
        if (!data || !Array.isArray(data) || data.length === 0) {
            throw new Error('No data available for export');
        }

        if (!columns || !Array.isArray(columns) || columns.length === 0) {
            throw new Error('Column definitions are required');
        }

        if (!res) {
            throw new Error('Express response object is required');
        }

        // Validate format
        const validFormats = ['csv', 'excel'];
        const exportFormat = validFormats.includes(format.toLowerCase()) 
            ? format.toLowerCase() 
            : 'csv';

        // Generate filename with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
        const sanitizedFileName = fileName.replace(/[^a-z0-9_-]/gi, '_');
        
        if (exportFormat === 'excel') {
            await exportToExcel({
                data,
                columns,
                res,
                fileName: sanitizedFileName,
                timestamp,
                excelOptions,
                metadata
            });
        } else {
            await exportToCsv({
                data,
                columns,
                res,
                fileName: sanitizedFileName,
                timestamp
            });
        }

    } catch (error) {
        console.error('Export error:', error);
        throw error;
    }
};

/**
 * Export data to Excel format
 */
const exportToExcel = async ({
    data,
    columns,
    res,
    fileName,
    timestamp,
    excelOptions = {},
    metadata = {}
}) => {
    const {
        sheetName = 'Sheet1',
        autoFilter = true,
        freezeHeader = true,
        alternateRows = true,
        cellFormatter = null,
        headerColor = 'FF4472C4',
        headerTextColor = 'FFFFFFFF'
    } = excelOptions;

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet(sheetName);

    // Add metadata
    workbook.creator = metadata.creator || 'Export System';
    workbook.created = new Date();
    workbook.modified = new Date();
    workbook.lastModifiedBy = metadata.modifiedBy || 'Export System';

    // Define columns
    worksheet.columns = columns.map(col => ({
        header: col.header || col.key,
        key: col.key,
        width: col.width || 15
    }));

    // Style header row
    const headerRow = worksheet.getRow(1);
    headerRow.font = { bold: true, size: 12 };
    headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: headerColor }
    };
    headerRow.font = { bold: true, size: 12, color: { argb: headerTextColor } };
    headerRow.alignment = { vertical: 'middle', horizontal: 'center' };
    headerRow.height = 20;

    // Add data rows
    data.forEach((item, index) => {
        const row = worksheet.addRow(item);
        
        // Alternate row colors
        if (alternateRows && index % 2 === 0) {
            row.fill = {
                type: 'pattern',
                pattern: 'solid',
                fgColor: { argb: 'FFF2F2F2' }
            };
        }

        // Apply custom cell formatting if provided
        if (cellFormatter && typeof cellFormatter === 'function') {
            cellFormatter(row, item, index, worksheet);
        }
    });

    // Freeze header row
    if (freezeHeader) {
        worksheet.views = [
            { state: 'frozen', ySplit: 1 }
        ];
    }

    // Add filters to header row
    if (autoFilter) {
        const lastColumn = String.fromCharCode(64 + columns.length);
        worksheet.autoFilter = {
            from: 'A1',
            to: `${lastColumn}1`
        };
    }

    // Generate full filename
    const fullFileName = `${fileName}-${timestamp}.xlsx`;

    // Set response headers
    res.setHeader(
        'Content-Type',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader(
        'Content-Disposition',
        `attachment; filename="${fullFileName}"`
    );
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Write to response using streaming
    await workbook.xlsx.write(res);
    res.end();
};

/**
 * Export data to CSV format
 */
const exportToCsv = async ({
    data,
    columns,
    res,
    fileName,
    timestamp
}) => {
    const exportDir = path.join(__dirname, '../exports');
    const fullFileName = `${fileName}-${timestamp}.csv`;
    const filePath = path.join(exportDir, fullFileName);

    try {
        // Ensure exports directory exists
        if (!fsSync.existsSync(exportDir)) {
            await fs.mkdir(exportDir, { recursive: true });
        }

        // Create CSV writer
        const csvWriter = createCsvWriter({
            path: filePath,
            header: columns.map(col => ({
                id: col.key,
                title: col.header || col.key
            }))
        });

        // Write records
        await csvWriter.writeRecords(data);

        // Set response headers
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader(
            'Content-Disposition',
            `attachment; filename="${fullFileName}"`
        );
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        // Send file for download
        res.download(filePath, fullFileName, async (err) => {
            if (err) {
                console.error('Error downloading file:', err);
                throw err;
            }

            // Delete file after download
            try {
                await fs.unlink(filePath);
            } catch (unlinkError) {
                console.error('Error deleting temporary file:', unlinkError);
                // Don't throw error as download was successful
            }
        });

    } catch (fileError) {
        console.error('CSV file system error:', fileError);
        throw fileError;
    }
};

/**
 * Utility function to format audit log data
 * @param {Array} logs - Array of audit log records
 * @returns {Array} Formatted logs ready for export
 */
const formatAuditLogs = (logs) => {
    return logs.map(log => ({
        ID: log.id,
        Action: log.action,
        'User ID': log.userId,
        'IP Address': log.ipAddress,
        'User Agent': log.userAgent || 'N/A',
        'Device Type': log.deviceType || 'Unknown',
        Country: log.country || 'N/A',
        City: log.city || 'N/A',
        'Risk Level': log.riskLevel,
        Timestamp: new Date(log.timestamp).toISOString(),
        Success: log.success ? 'Yes' : 'No',
        Details: log.details ? JSON.stringify(log.details) : '{}'
    }));
};

/**
 * Custom cell formatter for audit logs
 * @param {Object} row - Excel row object
 * @param {Object} item - Data item
 * @param {number} index - Row index
 * @param {Object} worksheet - Excel worksheet object
 */
const auditLogCellFormatter = (row, item, index, worksheet) => {
    // Color code risk levels
    const riskCell = row.getCell('Risk Level');
    switch (item['Risk Level']) {
        case 'HIGH':
            riskCell.font = { color: { argb: 'FFFF0000' }, bold: true };
            break;
        case 'MEDIUM':
            riskCell.font = { color: { argb: 'FFFF9900' }, bold: true };
            break;
        case 'LOW':
            riskCell.font = { color: { argb: 'FF00AA00' } };
            break;
    }

    // Color code success/failure
    const successCell = row.getCell('Success');
    if (item.Success === 'No') {
        successCell.font = { color: { argb: 'FFFF0000' }, bold: true };
    } else {
        successCell.font = { color: { argb: 'FF00AA00' } };
    }
};

/**
 * Define column structure for audit logs
 */
const auditLogColumns = [
    { key: 'ID', header: 'ID', width: 10 },
    { key: 'Action', header: 'Action', width: 20 },
    { key: 'User ID', header: 'User ID', width: 15 },
    { key: 'IP Address', header: 'IP Address', width: 15 },
    { key: 'User Agent', header: 'User Agent', width: 30 },
    { key: 'Device Type', header: 'Device Type', width: 15 },
    { key: 'Country', header: 'Country', width: 15 },
    { key: 'City', header: 'City', width: 15 },
    { key: 'Risk Level', header: 'Risk Level', width: 12 },
    { key: 'Timestamp', header: 'Timestamp', width: 25 },
    { key: 'Success', header: 'Success', width: 10 },
    { key: 'Details', header: 'Details', width: 40 }
];

module.exports = {
    exportData,
    exportToExcel,
    exportToCsv,
    formatAuditLogs,
    auditLogCellFormatter,
    auditLogColumns
};
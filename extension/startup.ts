import {
    workspace, languages, window, commands,
    ExtensionContext, Disposable, QuickPickItem, Uri, Event, EventEmitter, OutputChannel, ConfigurationTarget,
    WorkspaceFolder, WorkspaceConfiguration
} from 'vscode';
import { format, inspect } from 'util';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as ver from './ver';
import * as util from './util';
import { output, Dict } from './extension';

export class AdapterProcess {
    public isAlive: boolean;
    public port: number;

    constructor(process: cp.ChildProcess) {
        this.process = process;
        this.isAlive = true;
        process.on('exit', (code, signal) => {
            this.isAlive = false;
            if (signal) {
                output.appendLine(format('Adapter terminated by %s signal.', signal));
            }
            if (code) {
                output.appendLine(format('Adapter exit code: %d.', code));
            }
        });
    }
    public terminate() {
        if (this.isAlive) {
            this.process.kill();
        }
    }
    process: cp.ChildProcess;
}

// Start debug adapter in TCP session mode and return the port number it is listening on.
export async function startDebugAdapter(
    context: ExtensionContext,
    folder: WorkspaceFolder | undefined,
    params: Dict<any>
): Promise<AdapterProcess> {
    let config = workspace.getConfiguration('lldb', folder ? folder.uri : undefined);
    let paramsBase64 = getAdapterParameters(config, params);
    var args: string[];
    let lldbPath: string;
    let lldbEnv = config.get('executable_env', {});
    if (!config.get('useCodeLLDB', false)) {
        let adapterPath = path.join(context.extensionPath, 'adapter');
        args = ['-b',
            '-O', format('command script import \'%s\'', adapterPath),
            '-O', format('script adapter.main.run_tcp_session(0, \'%s\')', paramsBase64)
        ];
        lldbPath = config.get('executable', 'lldb');
    } else {
        args = [];
        lldbPath =  path.join(context.extensionPath, 'out/adapter2/codelldb');
    }
    let lldb = spawnDebugger(args, lldbPath, lldbEnv);
    let regex = new RegExp('^Listening on port (\\d+)\\s', 'm');
    let match = await waitPattern(lldb, regex);

    let adapter = new AdapterProcess(lldb);
    adapter.port = parseInt(match[1]);
    return adapter;
}

export async function launchDebugServer(context: ExtensionContext) {
    let config = workspace.getConfiguration('lldb', null);
    let adapterPath = path.join(context.extensionPath, 'adapter');
    let paramsBase64 = getAdapterParameters(config, {});
    let lldbPath = config.get('executable', 'lldb');

    let command =
        format('%s -b -O "command script import \'%s\'" ', lldbPath, adapterPath) +
        format('-O "script adapter.main.run_tcp_server()"\n');
    let terminal = window.createTerminal('LLDB Debug Server');
    terminal.sendText(command);
    terminal.show(true);
}

function setIfDefined(target: Dict<any>, config: WorkspaceConfiguration, key: string) {
    let value = util.getConfigNoDefault(config, key);
    if (value !== undefined)
        target[key] = value;
}

function getAdapterParameters(config: WorkspaceConfiguration, params: Dict<any>): string {
    setIfDefined(params, config, 'logLevel');
    setIfDefined(params, config, 'loggers');
    setIfDefined(params, config, 'logFile');
    setIfDefined(params, config, 'reverseDebugging');
    setIfDefined(params, config, 'suppressMissingSourceFiles');
    setIfDefined(params, config, 'evaluationTimeout');
    setIfDefined(params, config, 'ptvsd');
    return new Buffer(JSON.stringify(params)).toString('base64');
}

enum DiagnosticsStatus {
    Succeeded = 0,
    Warning = 1,
    Failed = 2,
    NotFound = 3
}

export async function diagnose(): Promise<boolean> {
    output.clear();
    var status = DiagnosticsStatus.Succeeded;
    try {
        output.appendLine('--- Checking version ---');
        var versionPattern = '^lldb version ([0-9.]+)';
        var desiredVersion = '3.9.1';
        if (process.platform.includes('win32')) {
            desiredVersion = '4.0.0';
        } else if (process.platform.includes('darwin')) {
            versionPattern = '^lldb-([0-9.]+)';
            desiredVersion = '360.1.68';
        }
        let pattern = new RegExp(versionPattern, 'm');

        let config = workspace.getConfiguration('lldb', null);
        let lldbPathOrginal = config.get('executable', 'lldb');
        let lldbPath = lldbPathOrginal;
        let lldbEnv = config.get('executable_env', {});

        // Try to locate LLDB and get its version.
        var version: string = null;
        var lldbNames: string[];
        if (process.platform.includes('linux')) {
            // Linux tends to have versioned binaries only.
            lldbNames = ['lldb', 'lldb-10.0', 'lldb-9.0', 'lldb-8.0', 'lldb-7.0',
                'lldb-6.0', 'lldb-5.0', 'lldb-4.0', 'lldb-3.9'];
        } else {
            lldbNames = ['lldb'];
        }
        if (lldbPathOrginal != 'lldb') {
            lldbNames.unshift(lldbPathOrginal); // Also try the explicitly configured value.
        }
        for (var name of lldbNames) {
            try {
                let lldb = spawnDebugger(['-v'], name, lldbEnv);
                version = (await waitPattern(lldb, pattern))[1];
                lldbPath = name;
                break;
            } catch (err) {
                output.appendLine(inspect(err));
            }
        }

        if (!version) {
            status = DiagnosticsStatus.NotFound;
        } else {
            if (ver.lt(version, desiredVersion)) {
                output.appendLine(
                    format('Warning: The version of your LLDB was detected as %s, which had never been tested with this extension. ' +
                        'Please consider upgrading to least version %s.',
                        version, desiredVersion));
                status = DiagnosticsStatus.Warning;
            }

            // Check if Python scripting is usable.
            output.appendLine('--- Checking Python ---');
            let lldb2 = spawnDebugger(['-b',
                '-O', 'script import sys, io, lldb',
                '-O', 'script print(lldb.SBDebugger.Create().IsValid())',
                '-O', 'script print("OK")'
            ], lldbPath, lldbEnv);
            // [^] = match any char, including newline
            let match2 = await waitPattern(lldb2, new RegExp('^True$[^]*^OK$', 'm'));
        }
        output.appendLine('--- Done ---');
        output.show(true);

        // If we updated lldbPath, ask user what to do.
        if (lldbPathOrginal != lldbPath) {
            let action = await window.showInformationMessage(
                format('Could not launch LLDB executable "%s", ' +
                    'however we did locate a usable LLDB binary: "%s". ' +
                    'Would you like to update LLDB configuration with this value?',
                    lldbPathOrginal, lldbPath),
                'Yes', 'No');
            if (action == 'Yes') {
                output.appendLine('Setting "lldb.executable": "' + lldbPath + '".');
                config.update('executable', lldbPath, ConfigurationTarget.Global);
            } else {
                status = DiagnosticsStatus.Failed;
            }
        }
    } catch (err) {
        output.appendLine('');
        output.appendLine('*** An exception was raised during self-test ***');
        output.appendLine(inspect(err));
        status = DiagnosticsStatus.Failed;
    }
    output.show(true);
    switch (<number>status) {
        case DiagnosticsStatus.Succeeded:
            window.showInformationMessage('LLDB self-test completed successfuly.');
            break;
        case DiagnosticsStatus.Warning:
            window.showWarningMessage('LLDB self-test completed with warnings.  Please check LLDB output panel for details.');
            break;
        case DiagnosticsStatus.Failed:
            window.showErrorMessage('LLDB self-test has failed!');
            break;
        case DiagnosticsStatus.NotFound:
            let action = await window.showErrorMessage('Could not find LLDB on your system.', 'Show installation instructions');
            if (action != null)
                commands.executeCommand('vscode.open', Uri.parse('https://github.com/vadimcn/vscode-lldb/wiki/Installing-LLDB'));
            break;
    }
    return status < DiagnosticsStatus.Failed;
}

// Spawn LLDB with the specified arguments, wait for it to output something matching
// regex pattern, or until the timeout expires.
function spawnDebugger(args: string[], lldbPath: string, lldbEnv: Dict<string>): cp.ChildProcess {
    let env = Object.assign({}, process.env);
    for (var key in lldbEnv) {
        env[key] = util.expandVariables(lldbEnv[key], (type, key) => {
            if (type == 'env') return process.env[key];
            throw new Error('Unknown variable type ' + type);
        });
    }

    let options = {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: env,
        cwd: workspace.rootPath
    };
    if (process.platform.includes('darwin')) {
        // Make sure LLDB finds system Python before Brew Python
        // https://github.com/Homebrew/legacy-homebrew/issues/47201
        options.env['PATH'] = '/usr/bin:' + process.env['PATH'];
    }
    return cp.spawn(lldbPath, args, options);
}

async function waitPattern(lldb: cp.ChildProcess, pattern: RegExp, timeout_millis = 5000) {
    lldb.stdout.on('data', (chunk) => {
        output.append(chunk.toString()); // Send to "LLDB" output pane.
    });
    // Send sdterr to the output pane as well.
    lldb.stderr.on('data', (chunk) => {
        output.append(chunk.toString());
    });
    return util.waitForPattern(lldb, lldb.stdout, pattern, timeout_millis);
}

export async function analyzeStartupError(err: Error) {
    output.appendLine(err.toString());
    output.show(true)
    let e = <any>err;
    let diagnostics = 'Run diagnostics';
    var actionAsync;
    if (e.code == 'ENOENT') {
        actionAsync = window.showErrorMessage(
            format('Could not start debugging because executable \'%s\' was not found.', e.path),
            diagnostics);
    } else if (e.code == 'Timeout' || e.code == 'Handshake') {
        actionAsync = window.showErrorMessage(err.message, diagnostics);
    } else {
        actionAsync = window.showErrorMessage('Could not start debugging.', diagnostics);
    }

    if ((await actionAsync) == diagnostics) {
        await diagnose();
    }
}

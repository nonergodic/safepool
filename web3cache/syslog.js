module.exports = function (componentName) {
    const start = '>>>>>>>>>>>>>>>>'
    const end   = '<<<<<<<<<<<<<<<<'
    return {
        line: {
            log:   (...args) =>   console.log(componentName+':', ...args),
            warn:  (...args) =>  console.warn(componentName+':', ...args),
            error: (...args) => console.error(componentName+':', ...args)
        },
        chunk: {
            log:   (...args) =>   console.log(start, componentName+':\n', ...args, '\n'+end, componentName),
            warn:  (...args) =>  console.warn(start, componentName+':\n', ...args, '\n'+end, componentName),
            error: (...args) => console.error(start, componentName+':\n', ...args, '\n'+end, componentName)
        }
    }
}